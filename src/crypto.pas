unit Crypto;

{$mode objfpc}{$H+}
{$MODESWITCH ArrayOperators}

interface

uses
  Classes, SysUtils, SynCommons, SynCrypto, LCLIntf,
  ClpIECPrivateKeyParameters, ClpIECPublicKeyParameters, ClpIEphemeralKeyPair, ClpIAsymmetricKeyParameter;

type

  IECPrivateKeyParameters = ClpIECPrivateKeyParameters.IECPrivateKeyParameters;
  IECPublicKeyParameters = ClpIECPublicKeyParameters.IECPublicKeyParameters;

  { TCrypto }

  TCrypto = class
  public
    class procedure GeneratePairKey(out APrivateKey: IECPrivateKeyParameters; out APublicKey: IECPublicKeyParameters);
    class function GeneratePrivateKey: IECPrivateKeyParameters;

    class function Sign(const AData: RawByteString; APrivateKey: IECPrivateKeyParameters): RawByteString;
    class function Verify(const AData, ASign: RawByteString; APublicKey: IECPublicKeyParameters): boolean;

    class function Encrypt(const AKey: IECPublicKeyParameters; const AInput: RawByteString; out AOutput: RawByteString): boolean; overload;
    class function Decrypt(const AKey: IECPrivateKeyParameters; const AInput: RawByteString; out AOutput: RawByteString): boolean; overload;
    class function Decrypt(const AKey: IECPrivateKeyParameters; const AIV, AEphemeralPK, AMac, AInput: TBytes; out AOutput: RawByteString): boolean; overload;
    class function Decrypt(const AKey: IECPrivateKeyParameters; const AIV, AEphemeralPK, AMac, AInput: RawByteString; out AOutput: RawByteString): boolean; overload;
    class function DecryptHexJSONObejct(const AKey: IECPrivateKeyParameters; const AInput: RawByteString; out AOutput: RawByteString): boolean;

    class function Encrypt(const AKey: RawUTF8; const AInput: RawByteString; ALength: integer; out AOutput: RawByteString): boolean; overload;
    class function Decrypt(const AKey: RawUTF8; const AInput: RawByteString; out AOutput: RawByteString): boolean; overload;

    class function EncryptPKCS7(const AKey: RawUTF8; const ASalt: RawByteString; ARounds: integer; const AInput: RawByteString; AIVAtBeginning: boolean): RawByteString;

    class function JWTEncode(const APayload: RawByteString; APrivateKey: IECPrivateKeyParameters): RawByteString;
    class function JWTDecode(const AData: RawByteString; out AHeadPayload: RawUTF8; out ADecodedPayload, ASignature: RawByteString): boolean;

    class function PublicKeyFromPrivateKey(APrivateKey: IECPrivateKeyParameters): IECPublicKeyParameters;

    class function StringToPrivateKey(APrivateKey: string): IECPrivateKeyParameters;
    class function StringToPublicKey(APublicKey: RawUTF8): IECPublicKeyParameters;
    class function PrivateKeyAsString(APrivateKey: IECPrivateKeyParameters): RawUTF8;
    class function PublicKeyAsString(APublicKey: IECPublicKeyParameters): RawUTF8;
    class function PublicKeyAsAddress(APublicKey: IECPublicKeyParameters): RawUTF8;

    class function RandomURLSafePassword(Len: integer): RawUTF8;
  end;

implementation

uses
  ClpECKeyPairGenerator, ClpCustomNamedCurves, ClpIX9ECParameters, ClpIECDomainParameters,
  ClpECDomainParameters, ClpBigInteger, ClpCryptoLibTypes, ClpECPrivateKeyParameters,
  ClpECPublicKeyParameters, ClpIAesEngine, ClpAesEngine, ClpSecureRandom, ClpPaddingModes,
  ClpMacUtilities, ClpBlockCipherModes, ClpECDHBasicAgreement, ClpPaddedBufferedBlockCipher,
  ClpECKeyGenerationParameters, ClpIECKeyGenerationParameters, ClpIECKeyParameters,
  ClpEphemeralKeyPairGenerator, ClpKeyEncoder, ClpIKeyEncoder, ClpParametersWithIV,
  ClpIParametersWithIV, ClpKeyParameter, ClpIKeyParameter, ClpBigIntegers, ClpArrayUtils,
  ECDSASigner, HlpRIPEMD160, ClpEncoders, ClpDigestUtilities, ClpIBasicAgreement,
  ClpIBufferedBlockCipher, ClpIBlockCipherModes, ClpIECIESPublicKeyParser,
  ClpECIESPublicKeyParser, ClpIPaddingModes, ClpIPaddedBufferedBlockCipher,
  ClpIECDHBasicAgreement, ClpIEphemeralKeyPairGenerator, ClpIECKeyPairGenerator, ClpISecureRandom;

{ TCrypto }

class procedure TCrypto.GeneratePairKey(out APrivateKey: IECPrivateKeyParameters; out APublicKey: IECPublicKeyParameters);
var
  NamedCurve: IX9ECParameters;
  ECDomainParameters: IECDomainParameters;
  PG: IECKeyPairGenerator;
  SR: ISecureRandom;
  KGP: IECKeyGenerationParameters;
begin
  NamedCurve := TCustomNamedCurves.GetByName('secp256k1');
  with NamedCurve do
    ECDomainParameters := TECDomainParameters.Create(Curve, G, N, H, GetSeed);

  PG := TECKeyPairGenerator.Create('ECDSA');
  SR := TSecureRandom.Create;
  KGP := TECKeyGenerationParameters.Create(ECDomainParameters, SR);
  PG.Init(KGP);
  with PG.GenerateKeyPair do
  begin
    APrivateKey := Private as IECPrivateKeyParameters;
    APublicKey := Public as IECPublicKeyParameters;
  end;
end;

class function TCrypto.GeneratePrivateKey: IECPrivateKeyParameters;
var
  Pub: IECPublicKeyParameters;
begin
  GeneratePairKey(Result, Pub);
end;

class function TCrypto.Sign(const AData: RawByteString; APrivateKey: IECPrivateKeyParameters): RawByteString;
begin
  Result := ECDSASigner.Sign(AData, APrivateKey);
end;

class function TCrypto.Verify(const AData, ASign: RawByteString; APublicKey: IECPublicKeyParameters): boolean;
begin
  Result := ECDSASigner.Verify(AData, ASign, APublicKey);
end;

procedure SharedSecretToKeys(const ASharedSecret: TBytes; out AEncryptionKey: TBytes; out AHMacKey: TBytes);
var
  hashedSecret: TBytes;
begin
  hashedSecret := TDigestUtilities.CalculateDigest('SHA-512', ASharedSecret);
  AEncryptionKey := Copy(hashedSecret, 0, 32);
  AHMacKey := Copy(hashedSecret, 32, 32);
end;

class function TCrypto.Encrypt(const AKey: IECPublicKeyParameters; const AInput: RawByteString; out AOutput: RawByteString): boolean;
var
  ECParams: IECDomainParameters;
  ECKeyPairGen: IECKeyPairGenerator;
  SecureRandom: ISecureRandom;
  EphemeralKeyPairGenerator: IEphemeralKeyPairGenerator;
  EphemeralSK: IEphemeralKeyPair;
  EphemeralPrivateKey: IAsymmetricKeyParameter;
  EphemeralPKBytes, SharedSecretBytes: TCryptoLibByteArray;
  ECDHBasicAgreementInstance: IECDHBasicAgreement;
  SharedSecret: TBigInteger;
  InputBytes, IV, CipherText, MacData: TBytes;
  Mac, EncryptionKey, HMacKey: TBytes;
  AESEngine: IAesEngine;
  CBCBlockCipher: ICbcBlockCipher;
  PaddedBufferedBlockCipher: IPaddedBufferedBlockCipher;
begin
  RawByteStringToBytes(AInput, InputBytes);
  ECParams := (AKey as IECKeyParameters).Parameters;
  SecureRandom := TSecureRandom.Create();
  ECKeyPairGen := TECKeyPairGenerator.Create();
  ECKeyPairGen.Init(TECKeyGenerationParameters.Create(ECParams, SecureRandom) as IECKeyGenerationParameters);
  EphemeralKeyPairGenerator := TEphemeralKeyPairGenerator.Create(ECKeyPairGen, TKeyEncoder.Create(True) as IKeyEncoder);
  EphemeralSK := EphemeralKeyPairGenerator.Generate;
  EphemeralPrivateKey := EphemeralSK.GetKeyPair.Private;
  EphemeralPKBytes := EphemeralSK.GetEncodedPublicKey;
  ECDHBasicAgreementInstance := TECDHBasicAgreement.Create;
  ECDHBasicAgreementInstance.Init(EphemeralPrivateKey);
  SharedSecret := ECDHBasicAgreementInstance.CalculateAgreement(AKey);
  SharedSecretBytes := TBigIntegers.AsUnsignedByteArray(ECDHBasicAgreementInstance.GetFieldSize, SharedSecret);
  SharedSecretToKeys(SharedSecretBytes, EncryptionKey, HMacKey);
  IV := nil;
  SetLength(IV, 16);
  SecureRandom.NextBytes(IV);
  AESEngine := TAesEngine.Create;
  CBCBlockCipher := TCbcBlockCipher.Create(AESEngine);
  PaddedBufferedBlockCipher := TPaddedBufferedBlockCipher.Create(CBCBlockCipher, TPkcs7Padding.Create as IPkcs7Padding);
  PaddedBufferedBlockCipher.Init(True, TParametersWithIV.Create(TKeyParameter.Create(EncryptionKey) as IKeyParameter, IV) as IParametersWithIV);
  CipherText := PaddedBufferedBlockCipher.DoFinal(InputBytes);
  MacData := TArrayUtils.Concatenate(IV, TCryptoLibMatrixByteArray.Create(EphemeralPKBytes, CipherText));
  Mac := TMacUtilities.CalculateMac('HMAC-SHA256', TKeyParameter.Create(HMacKey) as IKeyParameter, MacData);
  BytesToRawByteString(IV + EphemeralPKBytes + Mac + CipherText, AOutput);
  Result := True;
end;

class function TCrypto.Decrypt(const AKey: IECPrivateKeyParameters; const AInput: RawByteString; out AOutput: RawByteString): boolean;
var
  IV, EphemeralPK, Mac, Input: TBytes;
begin
  RawByteStringToBytes(AInput, Input);
  IV := Copy(Input, 0, 16);
  EphemeralPK := Copy(Input, 16, 33);
  Mac := Copy(Input, 49, 32);
  Input := Copy(Input, 81, Length(Input) - 81);
  Result := Decrypt(AKey, IV, EphemeralPK, Mac, Input, AOutput);
end;

class function TCrypto.Decrypt(const AKey: IECPrivateKeyParameters; const AIV, AEphemeralPK, AMac, AInput: TBytes; out AOutput: RawByteString): boolean;
var
  ECParams: IECDomainParameters;
  EphemeralPK: IAsymmetricKeyParameter;
  SharedSecretBytes, ActualMac, EncryptionKey, HMacKey, MacData: TBytes;
  ECDHBasicAgreementInstance: IBasicAgreement;
  SharedSecret: TBigInteger;
  AESEngine: IAesEngine;
  KeyParser: IECIESPublicKeyParser;
  EphemeralStream: TBytesStream;
  CBCBlockCipher: ICbcBlockCipher;
  PaddedBufferedBlockCipher: IPaddedBufferedBlockCipher;
begin
  Result := False;
  ECParams := (AKey as IECKeyParameters).Parameters;
  KeyParser := TECIESPublicKeyParser.Create(ECParams) as IECIESPublicKeyParser;
  EphemeralStream := TBytesStream.Create(AEphemeralPK);
  try
    EphemeralStream.Position := 0;
    try
      EphemeralPK := KeyParser.ReadKey(EphemeralStream);
    except
      Exit;
    end;
  finally
    EphemeralStream.Free
  end;
  ECDHBasicAgreementInstance := TECDHBasicAgreement.Create;
  ECDHBasicAgreementInstance.Init(AKey);
  SharedSecret := ECDHBasicAgreementInstance.CalculateAgreement(EphemeralPK);
  SharedSecretBytes := TBigIntegers.AsUnsignedByteArray(ECDHBasicAgreementInstance.GetFieldSize, SharedSecret);
  SharedSecretToKeys(SharedSecretBytes, EncryptionKey, HMacKey);
  MacData := TArrayUtils.Concatenate(AIV, TCryptoLibMatrixByteArray.Create(AEphemeralPK, AInput));
  ActualMac := TMacUtilities.CalculateMac('HMAC-SHA256', TKeyParameter.Create(HMacKey) as IKeyParameter, MacData);
  if not TArrayUtils.ConstantTimeAreEqual(AMac, ActualMac) then
    Exit;
  AESEngine := TAesEngine.Create;
  CBCBlockCipher := TCbcBlockCipher.Create(AESEngine);
  PaddedBufferedBlockCipher := TPaddedBufferedBlockCipher.Create(CBCBlockCipher, TPkcs7Padding.Create as IPkcs7Padding);
  PaddedBufferedBlockCipher.Init(False, TParametersWithIV.Create(TKeyParameter.Create(EncryptionKey) as IKeyParameter, AIV) as IParametersWithIV);
  BytesToRawByteString(PaddedBufferedBlockCipher.DoFinal(AInput), AOutput);
  Result := True;
end;

class function TCrypto.Decrypt(const AKey: IECPrivateKeyParameters; const AIV, AEphemeralPK, AMac, AInput: RawByteString; out AOutput: RawByteString): boolean;
var
  IV, EphemeralPK, Mac, Input: TBytes;
begin
  RawByteStringToBytes(AIV, IV);
  RawByteStringToBytes(AEphemeralPK, EphemeralPK);
  RawByteStringToBytes(AMac, Mac);
  RawByteStringToBytes(AInput, Input);
  Result := Decrypt(AKey, IV, EphemeralPK, Mac, Input, AOutput);
end;

class function TCrypto.DecryptHexJSONObejct(const AKey: IECPrivateKeyParameters; const AInput: RawByteString; out AOutput: RawByteString): boolean;
var
  Vs: array[0..3] of TValuePUTF8Char;
  Input: RawByteString;
begin
  Input := HexToBin(AInput);
  Result := JSONDecode(Pointer(Input), ['iv', 'ephemeralPK', 'mac', 'cipherText'], @Vs) <> nil;
  if not Result then
    Exit;
  Result := Result and TCrypto.Decrypt(AKey, HexToBin(VS[0].ToUTF8), HexToBin(VS[1].ToUTF8), HexToBin(VS[2].ToUTF8), HexToBin(VS[3].ToUTF8), AOutput);
end;

class function TCrypto.Encrypt(const AKey: RawUTF8; const AInput: RawByteString; ALength: integer; out AOutput: RawByteString): boolean;
var
  Enc: TAESCBC;
  Key: THash256;
begin
  HexToBin(@AKey[1], @Key[0], 32);
  Enc := TAESCBC.Create(Key);
  SetString(AOutput, nil, Enc.EncryptPKCS7Length(ALength, True));
  Result := Enc.EncryptPKCS7Buffer(Pointer(AInput), Pointer(AOutput), ALength, Length(AOutput), True);
  Enc.Free;
end;

class function TCrypto.Decrypt(const AKey: RawUTF8; const AInput: RawByteString; out AOutput: RawByteString): boolean;
var
  Enc: TAESCBC;
  Key: THash256;
begin
  HexToBin(@AKey[1], @Key[0], 32);
  Enc := TAESCBC.Create(Key);
  AOutput := Enc.DecryptPKCS7(AInput, True, True);
  Enc.Free;
  Result := True;
end;

class function TCrypto.EncryptPKCS7(const AKey: RawUTF8; const ASalt: RawByteString; ARounds: integer; const AInput: RawByteString; AIVAtBeginning: boolean): RawByteString;
var
  Enc: TAESCBC;
begin
    Enc := TAESCBC.CreateFromPBKDF2(aKey, aSalt, aRounds);
    Result := Enc.EncryptPKCS7(AInput, AIVAtBeginning);
    Enc.Free;
end;

class function TCrypto.JWTEncode(const APayload: RawByteString; APrivateKey: IECPrivateKeyParameters): RawByteString;
var
  HeadPayload: RawUTF8;
begin
  HeadPayload := BinToBase64uri('{"alg":"ES256K","typ":"JWT"}') + '.' + BinToBase64uri(APayload);
  Result := HeadPayload + '.' + BinToBase64uri(Sign(HeadPayload, APrivateKey));
end;

class function TCrypto.JWTDecode(const AData: RawByteString; out AHeadPayload: RawUTF8; out ADecodedPayload, ASignature: RawByteString): boolean;
var
  D: PAnsiChar absolute AData;
  DataLen, HeadLen, PayloadEnd: PtrInt;
  Head: RawByteString;
  HeadValues: array[0..1] of TValuePUTF8Char;
begin
  Result := False;
  DataLen := Length(AData);
  if DataLen = 0 then
    Exit;
  HeadLen := PosEx('.', AData);
  if (HeadLen = 0) or (HeadLen > 512) then
    Exit;
  Head := Base64URIToBin(D, HeadLen - 1);
  JSONDecode(Pointer(Head), ['alg', 'typ'], @HeadValues);
  if (not HeadValues[0].Idem('ES256K')) or (not HeadValues[1].Idem('JWT')) then
    Exit;
  PayloadEnd := PosEx('.', AData, HeadLen + 1);
  if (PayloadEnd = 0) or (PayloadEnd - HeadLen > 2700) then
    Exit;
  ASignature := Base64URIToBin(D + PayloadEnd, DataLen - PayloadEnd);
  ADecodedPayload := Base64URIToBin(D + HeadLen, PayloadEnd - HeadLen - 1);
  FastSetString(AHeadPayload, Pointer(AData), PayloadEnd - 1);
  Result := True;
end;

class function TCrypto.PublicKeyFromPrivateKey(APrivateKey: IECPrivateKeyParameters): IECPublicKeyParameters;
begin
  Result := TECKeyPairGenerator.GetCorrespondingPublicKey(APrivateKey);
end;

class function TCrypto.StringToPrivateKey(APrivateKey: string): IECPrivateKeyParameters;
var
  NC: IX9ECParameters;
  DP: IECDomainParameters;
  D: TBigInteger;
begin
  NC := TCustomNamedCurves.GetByName('secp256k1');
  DP := TECDomainParameters.Create(NC.Curve, NC.G, NC.N, NC.H, NC.GetSeed);
  D := TBigInteger.Create(APrivateKey, 16);
  Result := TECPrivateKeyParameters.Create('ECDSA', D, DP);
end;

class function TCrypto.StringToPublicKey(APublicKey: RawUTF8): IECPublicKeyParameters;
var
  NC: IX9ECParameters;
  DP: IECDomainParameters;
  D: TBigInteger;
begin
  NC := TCustomNamedCurves.GetByName('secp256k1');
  DP := TECDomainParameters.Create(NC.Curve, NC.G, NC.N, NC.H, NC.GetSeed);
  D := TBigInteger.Create(APublicKey, 16);
  Result := TECPublicKeyParameters.Create('ECDSA', NC.Curve.DecodePoint(D.ToByteArray()), DP);
end;

class function TCrypto.PrivateKeyAsString(APrivateKey: IECPrivateKeyParameters): RawUTF8;
var
  PBPB: TBytes;
begin
  PBPB := APrivateKey.D.ToByteArray;
  Result := BinToHexLower(Pointer(PBPB), Length(PBPB));
end;

class function TCrypto.PublicKeyAsString(APublicKey: IECPublicKeyParameters): RawUTF8;
var
  PBPB: TBytes;
begin
  PBPB := APublicKey.Q.Normalize.GetEncoded(True);
  Result := BinToHexLower(Pointer(PBPB), Length(PBPB));
end;

class function TCrypto.PublicKeyAsAddress(APublicKey: IECPublicKeyParameters): RawUTF8;
var
  SHA: TSHA256;
  BC, BCC: TBytes;
  Digest: TSHA256Digest;
begin
  BC := APublicKey.Q.Normalize.GetEncoded(True);
  SHA.Full(Pointer(BC), Length(BC), Digest);
  with TRIPEMD160.Create do
  begin
    BC := ComputeUntyped(Digest[0], Length(Digest)).GetBytes;
    Free;
  end;
  BC := [0] + BC;
  BCC := BC;
  SHA.Full(Pointer(BCC), Length(BCC), Digest);
  SetLength(BCC, Length(Digest));
  Move(Digest[0], BCC[0], Length(Digest));
  SHA.Full(Pointer(BCC), Length(BCC), Digest);
  SetLength(BCC, Length(Digest));
  Move(Digest[0], BCC[0], Length(Digest));
  BC += [BCC[0], BCC[1], BCC[2], BCC[3]];
  with TBase58.Create do
  begin
    Result := Encode(BC);
    Free;
  end;
end;

class function TCrypto.RandomURLSafePassword(Len: integer): RawUTF8;
const
  CHARS: array [0..61] of AnsiChar =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
var
  i: integer;
  P: PAnsiChar;
begin
  Result := TAESPRNG.Main.FillRandom(Len);
  P := pointer(Result);
  for i := 1 to Len do
  begin
    P^ := CHARS[Ord(P^) mod SizeOf(CHARS)];
    Inc(P);
  end;
end;

end.
