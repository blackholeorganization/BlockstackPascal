unit BlockStack;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SynCommons, mORMot, Network, Crypto;

type
  TBlockStackErrorKind = (bsekNone, bsekUnknown, beskInvalidInputPrivateKey, bsekInvalidResponse, beskMultiPublicKeys,
    beskInvalidSignature, beskInvalidAddress, beskInvalidUserName, beskInvalidPrivateKey);

  { TBlockStackAuthResponse }

  TBlockStackAuthResponse = class
  private
    Fiss: RawUTF8;
    Fprivate_key: RawUTF8;
    Fpublic_keys: TRawUTF8DynArray;
    Fusername: RawUTF8;
    Fversion: RawUTF8;
  published
    property iss: RawUTF8 read Fiss write Fiss;
    property private_key: RawUTF8 read Fprivate_key write Fprivate_key;
    property public_keys: TRawUTF8DynArray read Fpublic_keys write Fpublic_keys;
    property username: RawUTF8 read Fusername write Fusername;
    property version: RawUTF8 read Fversion write Fversion;
  end;

  { TBlockStack }

  TBlockStack = class
  private
    FActive: boolean;
    FHubURL: RawUTF8;
    FPrivateKey: IECPrivateKeyParameters;
    FPublicKey: IECPublicKeyParameters;
    FUsername: RawUTF8;
    procedure SetPrivateKey(AValue: IECPrivateKeyParameters);
  public
    constructor Create;
    function GenerateSignInURL(ARedirectURL, AManifestURL, ADomain: RawUTF8; APrivateKey: IECPrivateKeyParameters): RawUTF8;
    function HandleSignInResponse(const AResponse: RawUTF8; APrivateKey: IECPrivateKeyParameters): TBlockStackErrorKind;
  published
    property Active: boolean read FActive;
    property PrivateKey: IECPrivateKeyParameters read FPrivateKey write SetPrivateKey;
    property PublicKey: IECPublicKeyParameters read FPublicKey;
    property HubURL: RawUTF8 read FHubURL;
    property Username: RawUTF8 read FUsername;
  end;

const
  BLOCKSTACK_VERSION = '1.3.1';
  BLOCKSTACK_HOST = 'blockstack.org';
  BLOCKSTACK_AUTH = 'https://browser.blockstack.org/auth';
  BLOCKSTACK_CORE_NODE = 'https://core.blockstack.org';
  BLOCKSTACK_DEFAULT_GAIA_HUB_URL = 'https://hub.BlockStack.org';
  BLOCKSTACK_NAME_LOOKUP_PATH = '/v1/names/';

implementation

uses Math;

{ TBlockStack }

procedure TBlockStack.SetPrivateKey(AValue: IECPrivateKeyParameters);
begin
  if FPrivateKey = AValue then
    Exit;
  FPrivateKey := AValue;
  FPublicKey := TCrypto.PublicKeyFromPrivateKey(FPrivateKey);
  FActive := True;
end;

constructor TBlockStack.Create;
begin
  FActive := False;
  FHubURL := BLOCKSTACK_DEFAULT_GAIA_HUB_URL;
end;

function TBlockStack.GenerateSignInURL(ARedirectURL, AManifestURL, ADomain: RawUTF8; APrivateKey: IECPrivateKeyParameters): RawUTF8;
var
  PubKey: IECPublicKeyParameters;
  Req: RawUTF8;
begin
  PubKey := TCrypto.PublicKeyFromPrivateKey(APrivateKey);
  Req := JSONEncode([
    'jti', GUIDToString(RandomGUID),
    'iat', UnixTimeUTC,
    'exp', UnixTimeUTC + 3600,
    'domain_name', ADomain,
    'manifest_uri', AManifestURL,
    'redirect_uri', ARedirectURL,
    'version', BLOCKSTACK_VERSION,
    'do_not_include_profile', True,
    'supports_hub_url', True,
    'scopes', '[', 'store_write', 'publish_data', ']',
    'public_keys', '[', TCrypto.PublicKeyAsString(PubKey), ']',
    'iss', 'did:btc-addr:' + TCrypto.PublicKeyAsAddress(PubKey)]);
  Result := BLOCKSTACK_AUTH + '?authRequest=' + TCrypto.JWTEncode(Req, APrivateKey);
  //if not IsUrlValid(Pointer(Result)) then
  //  Result := UrlEncode(Result);
end;

function TBlockStack.HandleSignInResponse(const AResponse: RawUTF8; APrivateKey: IECPrivateKeyParameters): TBlockStackErrorKind;
var
  HeadPayload, Adrs: RawUTF8;
  Response, Signature: RawByteString;
  PubKey: IECPublicKeyParameters;
  AuthRes: TBlockStackAuthResponse;
  Er: TBlockStackErrorKind;

  function DoDecode: boolean;
  begin
    Result := TCrypto.JWTDecode(AResponse, HeadPayload, Response, Signature);
    if Result then
      JSONToObject(AuthRes, Pointer(Response), Result, nil, JSONTOOBJECT_TOLERANTOPTIONS)
    else
      Er := bsekInvalidResponse;
  end;

  function DoPublicKey: boolean;
  begin
    Result := Length(AuthRes.public_keys) = 1;
    if Result then
      PubKey := TCrypto.StringToPublicKey(AuthRes.public_keys[0])
    else
      Er := beskMultiPublicKeys;
  end;

  function DoSignature: boolean;
  begin
    Result := TCrypto.Verify(HeadPayload, Signature, PubKey);
    if not Result then
      Er := beskInvalidSignature;
  end;

  function DoAddress: boolean;
  begin
    Adrs := ('did:btc-addr:' + TCrypto.PublicKeyAsAddress(PubKey));
    Result := AuthRes.iss = Adrs;
    if not Result then
      Er := beskInvalidAddress;
  end;

  function DoUserName: boolean;
  var
    RC: integer;
  begin
    Result := True;
    Result := TNetwork.Fetch(BLOCKSTACK_CORE_NODE + BLOCKSTACK_NAME_LOOKUP_PATH + AuthRes.username, RC, Response);
    if Result then
      Result := 'did:btc-addr:' + JSONDecode(RawUTF8(Response), 'address') = Adrs;
    if not Result then
      Er := beskInvalidUserName;
  end;

  function DoPrivateKey: boolean;
  var
    PrivKey: RawByteString;
  begin
    Result := TCrypto.DecryptHexJSONObejct(APrivateKey, AuthRes.private_key, PrivKey);
    if Result then
      PrivateKey := TCrypto.StringToPrivateKey(PrivKey);
    if not Result then
      Er := beskInvalidPrivateKey;
  end;

var
  R: boolean;
begin
  if not Assigned(APrivateKey) then
    Exit(beskInvalidInputPrivateKey);
  AuthRes := TBlockStackAuthResponse.Create;
  try
    Er := bsekNone;
    R := DoDecode and DoPublicKey and DoSignature and DoAddress {and DoUserName} and DoPrivateKey;
    if R then
      FUsername := AuthRes.username;
  finally
    Result := Er;
    AuthRes.Free;
  end;
end;

end.
