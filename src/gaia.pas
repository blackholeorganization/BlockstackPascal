unit Gaia;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SynCommons, mORMot, Network, Crypto;

type

  { TGaiaHub }

  TGaiaHub = class
  private
    FHost: RawUTF8;
    FChallengeText: RawUTF8;
    FPrivateKey: IECPrivateKeyParameters;
    FUrlPerfix, FToken, FAddress: RawUTF8;
    function GetHubInfo: RawUTF8;
    function MakeAuthToken(const AChallenge: RawUTF8): RawUTF8;
    procedure SetHost(AValue: RawUTF8);
    procedure SetPrivateKey(AValue: IECPrivateKeyParameters);
  public
    function Prepare: boolean;
    function UpdateHubInfo: boolean;
    procedure SetHubInfo(AUrlPerfix, AChallengeText: RawUTF8);
    function Upload(const AFileName: TFileName; const AContent: RawByteString; Out APublicURL: RawUTF8; AContentType: RawUTF8 = ''): TNetworkErrorKind;
    function Download(const AFileName: TFileName; out AContent: RawByteString): TNetworkErrorKind;
    function Delete(const AFileName: TFileName): boolean;
    function ListFiles: TRawUTF8DynArray;
    function GetFileURL(const AFileName: TFileName; AStore: boolean = False): RawUTF8;
  published
    property Host: RawUTF8 read FHost write SetHost;
    property PrivateKey: IECPrivateKeyParameters read FPrivateKey write SetPrivateKey;
    property UrlPerfix: RawUTF8 read FUrlPerfix;
    property ChallengeText: RawUTF8 read FChallengeText;
    property Token: RawUTF8 read FToken;
    property Address: RawUTF8 read FAddress;
  end;

implementation

uses FileUtil, SynCrypto;

type

  { TGaiaFileList }

  TGaiaFileList = class
  private
    Fentries: TRawUTF8DynArray;
    Fpage: RawUTF8;
  published
    property entries: TRawUTF8DynArray read Fentries write Fentries;
    property page: RawUTF8 read Fpage write Fpage;
  end;

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
  if (FUrlPerfix <> '') and (FChallengeText <> '') then
  begin
    FToken := MakeAuthToken(FChallengeText);
    Result := True;
  end
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
  FChallengeText := Vs[1].ToUTF8;
  FToken := MakeAuthToken(FChallengeText);
end;

procedure TGaiaHub.SetHubInfo(AUrlPerfix, AChallengeText: RawUTF8);
begin
  FUrlPerfix := AUrlPerfix;
  FChallengeText := AChallengeText;
  FToken := MakeAuthToken(FChallengeText);
end;

function TGaiaHub.Upload(const AFileName: TFileName; const AContent: RawByteString; out APublicURL: RawUTF8; AContentType: RawUTF8): TNetworkErrorKind;
var
  RC: integer;
  R: RawByteString;
begin
  if AContentType = '' then
    AContentType := 'application/octet-stream';
  if TNetwork.Fetch(GetFileURL(AFileName, True), RC, R, ['Authorization: bearer ' + FToken], 'POST', AContent, AContentType) then
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

function TGaiaHub.Delete(const AFileName: TFileName): boolean;
var
  RC: integer;
  R: RawByteString;
begin
  Result := False;
  if (not TNetwork.Fetch(FormatString('%/delete/%/%', [FHost, FAddress, AFileName]), RC, R, ['Authorization: bearer ' + FToken], 'DELETE')) then
    Exit;
  Result := True;
end;

function TGaiaHub.ListFiles: TRawUTF8DynArray;
var
  page: string;
  RC, PLen: integer;
  R: RawByteString;
  o: TGaiaFileList;
  v: boolean;
begin
  SetLength(Result, 0);
  try
    o := TGaiaFileList.Create;
    page := JSONEncode(['page', nil]);
    repeat
      if (not TNetwork.Fetch(FormatString('%/list-files/%', [FHost, FAddress]), RC, R, ['Authorization: bearer ' + FToken], 'POST', page, 'application/json')) then
        Exit;
      JSONToObject(o, @R[1], v);
      if (not v) or (o.entries = nil) or (Length(o.entries) = 0) then
        Exit;
      PLen := Length(Result);
      SetLength(Result, PLen + Length(o.entries));
      Move(o.entries[0], Result[PLen], Length(o.entries));
      page := JSONEncode(['page', o.page]);
    until False;
  finally
    o.Free;
  end;
end;

function TGaiaHub.GetFileURL(const AFileName: TFileName; AStore: boolean): RawUTF8;
begin
  if AStore then
    Result := FormatString('%/store/%/%', [FHost, FAddress, AFileName])
  else
    Result := FormatString('%/%/%', [FUrlPerfix, FAddress, AFileName]);
end;

end.
