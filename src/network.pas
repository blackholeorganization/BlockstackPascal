unit Network;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SynCommons;

type
  TNetworkErrorKind = (nekNone, nekUnknown, nekNotFound, nekRequestEntityTooLarge, nekSSLError, nekFailedAuthentication, nekTemporarilyUnavailable);

  { TNetwork }

  TNetwork = class
    class function Fetch(AURL: string; out AResponseCode: integer; out AResponse: RawByteString; AHeaders: TRawUTF8DynArray = nil; AMethod: string = 'GET'; AData: RawUTF8 = ''; AMimeType: RawUTF8 = ''): boolean; overload;
    class function ResponseCodeToErrorKind(AResponseCode: integer): TNetworkErrorKind;
  end;

implementation

uses httpsend, ssl_openssl, ssl_openssl_lib;

{ TNetwork }

class function TNetwork.Fetch(AURL: string; out AResponseCode: integer; out AResponse: RawByteString; AHeaders: TRawUTF8DynArray; AMethod: string; AData: RawUTF8; AMimeType: RawUTF8): boolean;
var
  h: RawUTF8;
begin
  with THTTPSend.Create do
    try
      for h in AHeaders do
        Headers.Add(h);
      if (AMethod = 'POST') then
      begin
        MimeType := AMimeType;
        Document.Write(AData[1], Length(AData));
      end;
      Result := HTTPMethod(AMethod, AURL) and (ResultCode < 300);
      AResponseCode := ResultCode;
      SetString(AResponse, PChar(Document.Memory), Document.Size div SizeOf(char));
    finally
      Free;
    end;
end;

class function TNetwork.ResponseCodeToErrorKind(AResponseCode: integer): TNetworkErrorKind;
begin
  case AResponseCode of
    202: Result := nekNone;
    401: Result := nekFailedAuthentication;
    403: Result := nekRequestEntityTooLarge;
    404: Result := nekNotFound;
    500: Result := nekSSLError;
    503: Result := nekTemporarilyUnavailable;
    else
      Result := nekUnknown;
  end;
end;

end.
