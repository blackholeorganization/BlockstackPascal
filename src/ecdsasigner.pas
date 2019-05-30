unit ECDSASigner;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SynCommons, ClpIECPrivateKeyParameters, ClpIECPublicKeyParameters;

function Sign(const AData: RawByteString; APrivateKey: IECPrivateKeyParameters): RawByteString;
function Verify(const AData, ASign: RawByteString; APublicKey: IECPublicKeyParameters): boolean;

implementation

uses
  ClpIECDsaSigner, ClpECDsaSigner, ClpISigner,
  ClpDigestUtilities, ClpHMacDsaKCalculator, ClpIHMacDsaKCalculator, ClpDsaDigestSigner,
  ClpSignersEncodings, ClpIDigest;

function Sign(const AData: RawByteString; APrivateKey: IECPrivateKeyParameters): RawByteString;
var
  DB: TBytes;
  DU: IDigest;
  ES: IECDsaSigner;
  SG: ISigner;
begin
  DU := TDigestUtilities.GetDigest('SHA-256');
  ES := TECDsaSigner.Create(THMacDsaKCalculator.Create(DU) as IHMacDsaKCalculator) as IECDsaSigner;
  SG := TDsaDigestSigner.Create(ES, DU, TPlainDsaEncoding.Instance);
  SG.Init(True, APrivateKey);
  RawByteStringToBytes(AData, DB);
  SG.BlockUpdate(DB, 0, Length(DB));
  DB := SG.GenerateSignature;
  BytesToRawByteString(DB, Result);
end;

function Verify(const AData, ASign: RawByteString; APublicKey: IECPublicKeyParameters): boolean;
var
  DB: TBytes;
  DU: IDigest;
  ES: IECDsaSigner;
  SG: ISigner;
begin
  DU := TDigestUtilities.GetDigest('SHA-256');
  ES := TECDsaSigner.Create(THMacDsaKCalculator.Create(DU) as IHMacDsaKCalculator) as IECDsaSigner;
  SG := TDsaDigestSigner.Create(ES, DU, TPlainDsaEncoding.Instance);
  SG.Init(False, APublicKey);
  RawByteStringToBytes(AData, DB);
  SG.BlockUpdate(DB, 0, Length(DB));
  RawByteStringToBytes(ASign, DB);
  Result := SG.VerifySignature(DB);
end;

end.
