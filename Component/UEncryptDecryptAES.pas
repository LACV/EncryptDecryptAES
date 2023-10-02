unit UEncryptDecryptAES;

interface

uses
  // System.SysUtils, System.Classes;
  System.SysUtils, System.Classes, Vcl.Dialogs;

type
  TEncryptDecryptAES = class(TComponent)
  private
    fEncrypt: boolean;
    fTex: string;
    fDecrypt: boolean;
    procedure setEncrypt(const Value: boolean);
    procedure setText(const Value: string);
    procedure setDecrypt(const Value: boolean);

    function getVEncrypt(): string;
    function getVDecrypt(): string;

    function supportedCharacters(Str: string): boolean;
  protected
    { Protected declarations }
  public
    { Public declarations }
  published
    { Published declarations }
    property Text: string read fTex write setText;
    property Encrypt: boolean read fEncrypt write setEncrypt default false;
    property Decrypt: boolean read fDecrypt write setDecrypt default false;
    property VEncrypt: string read getVEncrypt;
    property VDecrypt: string read getVDecrypt;

  end;

procedure Register;

implementation

uses MEncryptDecryptAES;

procedure Register;
begin
  RegisterComponents('EncryptDecrypt', [TEncryptDecryptAES]);
end;

{ TEncryptDecryptAES }

{ TEncryptDecryptAES }

function TEncryptDecryptAES.getVDecrypt(): string;
begin
  case (fDecrypt = true) and (fEncrypt = false) of
    true:
      Result := MEncryptDecryptAES.DecryptPassword(fTex);
  end;
end;

function TEncryptDecryptAES.getVEncrypt(): string;
begin
  case (fEncrypt = true) and (fDecrypt = false) of
    true:
      Result := MEncryptDecryptAES.EncryptPassword(fTex);
  end;
end;

procedure TEncryptDecryptAES.setDecrypt(const Value: boolean);
begin
  fDecrypt := Value;
  case fDecrypt of
    true:
      begin

        case Length(fTex) mod 2 <> 0 of
          true:
            begin
              showmessage('Invalid hexadecimal string length.');
              fEncrypt := false;
              fDecrypt := false;
              fTex := '';
            end;
          false:
            begin
              fEncrypt := false;
              getVDecrypt;
            end;
        end;

      end;
  end;
end;

procedure TEncryptDecryptAES.setEncrypt(const Value: boolean);
begin
  fEncrypt := Value;
  case fEncrypt of
    true:
      begin
        fDecrypt := false;
        getVEncrypt;
      end;
  end;
end;

procedure TEncryptDecryptAES.setText(const Value: string);
begin
  fTex := Value;
end;

function TEncryptDecryptAES.supportedCharacters(Str: string): boolean;
const
  specialCharacters = '!@#$%^&*()_+[]{}|;:''",.<>?/\`~-=';
var
  i: integer;
begin
  for i := 0 to Length(Str) do
    if Pos(Str[i], specialCharacters) > 0 then
    begin
      Result := true;
    end
    else
    begin
      Result := false;
      exit
    end;
end;

end.
