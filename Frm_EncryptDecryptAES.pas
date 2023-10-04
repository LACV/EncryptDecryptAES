unit Frm_EncryptDecryptAES;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls;

type
  TFrmEncryptDecryptAES = class(TForm)
    PnInferior: TPanel;
    LbD: TLabel;
    BtnValidar: TButton;
    EdtPass: TEdit;
    Panel1: TPanel;
    Label1: TLabel;
    Panel2: TPanel;
    Label3: TLabel;
    Panel3: TPanel;
    Label4: TLabel;
    Panel4: TPanel;
    Label5: TLabel;
    Panel5: TPanel;
    Label6: TLabel;
    EdtSha: TEdit;
    EdtKey: TEdit;
    EdtEncrypt: TEdit;
    EdtDecrypt: TEdit;
    Panel6: TPanel;
    Label2: TLabel;
    EdtSha2: TEdit;
    Panel7: TPanel;
    Label7: TLabel;
    EdtSalt: TEdit;
    BtnComparar: TButton;
    EdtPass2: TEdit;
    LbVerificacion: TLabel;
    procedure BtnValidarClick(Sender: TObject);
    procedure BtnCompararClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FrmEncryptDecryptAES: TFrmEncryptDecryptAES;

implementation

{$R *.dfm}

uses MEncryptDecryptAES;

procedure TFrmEncryptDecryptAES.BtnCompararClick(Sender: TObject);
begin

  EdtSha2.Text := calcularHash(EdtPass2.Text, EdtSalt.Text);

  if verifyHash(EdtPass2.Text, EdtSalt.Text, EdtDecrypt.Text) then
  begin
    LbVerificacion.Caption := 'true';
  end
  else
  begin
    LbVerificacion.Caption := 'false';
  end;
end;

procedure TFrmEncryptDecryptAES.BtnValidarClick(Sender: TObject);
var
  e: string;
begin
  case EdtPass.Text = '' of
    true:
      begin
        ShowMessage('Campo Obligatorio');
      end;

    false:
      begin

        LbD.Caption := EdtPass.Text;
        EdtSalt.Text := GenerateSalt(32);
        EdtSha.Text := calcularHash(EdtPass.Text, EdtSalt.Text);
        EdtKey.Text := GenerateRandomKey(32);
        EdtEncrypt.Text := EncryptHash(EdtSha.Text, EdtKey.Text);
        EdtDecrypt.Text := DecryptHash(EdtEncrypt.Text, EdtKey.Text);

        EdtPass2.Enabled := true;
        BtnComparar.Enabled := true;
        EdtSha2.Enabled := true;
        LbVerificacion.Enabled := true;

        e := EncryptPassword(EdtPass.Text, EdtKey.Text);
        ShowMessage('E:=' + EncryptPassword(EdtPass.Text, EdtKey.Text));
        ShowMessage(' D:=' + DecryptPassword(e, EdtKey.Text));

      end;
  end;

end;

end.
