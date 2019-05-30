unit Gaia;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SynCommons, Network, Crypto;

type

  { TGaiaHub }

  TGaiaHub = class
  private
    FHost: RawUTF8;
    FPrivateKey: IECPrivateKeyParameters;
    FUrlPerfix, FToken, FAddress: RawUTF8;
    function GetHubInfo: RawUTF8;
    function MakeAuthToken(const AChallenge: RawUTF8): RawUTF8;
    procedure SetHost(AValue: RawUTF8);
    procedure SetPrivateKey(AValue: IECPrivateKeyParameters);
  public
    function Prepare: boolean;
    function UpdateHubInfo: boolean;
    procedure SetHubInfo(AUrlPerfix, AToken: RawUTF8);
    function Upload(const AFileName: TFileName; const AContent: RawByteString; Out APublicURL: RawUTF8; AContentType: RawUTF8 = ''): TNetworkErrorKind;
    function Download(const AFileName: TFileName; out AContent: RawByteString): TNetworkErrorKind;
    function GetFileURL(const AFileName: TFileName; AStore: boolean = False): RawUTF8;
  published
    property Host: RawUTF8 read FHost write SetHost;
    property PrivateKey: IECPrivateKeyParameters read FPrivateKey write SetPrivateKey;
    property UrlPerfix: RawUTF8 read FUrlPerfix;
    property Token: RawUTF8 read FToken;
  end;

implementation

uses FileUtil, SynCrypto;

{ TGaiaHub }

function TGaiaHub.GetHubInfo: RawUTF8;
var
  RC: integer;
  R: RawByteString;
begin
  if TNetwork.Fetch(FHost + '/hub_info', RC, R, []) then
    Result := R
  else
    Result := '';
end;

function TGaiaHub.MakeAuthToken(const AChallenge: RawUTF8): RawUTF8;
var
  iss, salt, payload: RawUTF8;
begin
  iss := TCrypto.PublicKeyAsString(TCrypto.PublicKeyFromPrivateKey(FPrivateKey));
  salt := TAESPRNG.Main.FillRandomHex(16);
  payload := JSONEncode(['gaiaChallenge', AChallenge, 'hubUrl', FHost, 'iss', iss, 'salt', salt]);
  Result := 'v1:' + TCrypto.JWTEncode(payload, FPrivateKey);
end;

procedure TGaiaHub.SetHost(AValue: RawUTF8);
begin
  if FHost = AValue then
    Exit;
  FHost := ExcludeTrailingPathDelimiter(AValue);
end;

procedure TGaiaHub.SetPrivateKey(AValue: IECPrivateKeyParameters);
begin
  if FPrivateKey = AValue then
    Exit;
  FPrivateKey := AValue;
  FAddress := TCrypto.PublicKeyAsAddress(TCrypto.PublicKeyFromPrivateKey(FPrivateKey));
end;

function TGaiaHub.Prepare: boolean;
begin
  if (FUrlPerfix <> '') and (FToken <> '') then
    Result := True
  else
    Result := UpdateHubInfo;
end;

function TGaiaHub.UpdateHubInfo: boolean;
var
  Info: RawUTF8;
  Vs: array [0..1] of TValuePUTF8Char;
begin
  Info := GetHubInfo;
  Result := JSONDecode(Pointer(Info), ['read_url_prefix', 'challenge_text'], @Vs) <> nil;
  if not Result then
    Exit;
  FUrlPerfix := ExcludeTrailingPathDelimiter(Vs[0].ToUTF8);
  FToken := MakeAuthToken(Vs[1].ToUTF8);
end;

procedure TGaiaHub.SetHubInfo(AUrlPerfix, AToken: RawUTF8);
begin
  FUrlPerfix := AUrlPerfix;
  FToken := AToken;
end;

function TGaiaHub.Upload(const AFileName: TFileName; const AContent: RawByteString; out APublicURL: RawUTF8; AContentType: RawUTF8): TNetworkErrorKind;
var
  RC: integer;
  R: RawByteString;
begin
  if AContentType = '' then
    AContentType := 'application/octet-stream';
  if TNetwork.Fetch(GetFileURL(AFileName, True), RC, R, ['Content-Type: ' + AContentType, 'Authorization: bearer ' + FToken], 'POST', AContent) then
    APublicURL := JSONDecode(RawUTF8(R), 'publicURL');
  Result := TNetwork.ResponseCodeToErrorKind(RC);
end;

function TGaiaHub.Download(const AFileName: TFileName; out AContent: RawByteString): TNetworkErrorKind;
var
  RC: integer;
begin
  TNetwork.Fetch(GetFileURL(AFileName), RC, AContent);
  Result := TNetwork.ResponseCodeToErrorKind(RC);
end;

function TGaiaHub.GetFileURL(const AFileName: TFileName; AStore: boolean): RawUTF8;
begin
  if AStore then
    Result := FormatString('%/store/%/%', [FHost, FAddress, AFileName])
  else
    Result := FormatString('%/%/%', [FUrlPerfix, FAddress, AFileName]);
end;

end.
