unit Frm_EncryptDecryptAES;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls;

type
  TFrmEncryptDecryptAES = class(TForm)
    PnInferior: TPanel;
    LbE: TLabel;
    LbD: TLabel;
    BtnGuardar: TButton;
    EdtPass: TEdit;
    procedure BtnGuardarClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FrmEncryptDecryptAES: TFrmEncryptDecryptAES;

implementation

{$R *.dfm}

uses D_moduloED;

procedure TFrmEncryptDecryptAES.BtnGuardarClick(Sender: TObject);
begin
  case EdtPass.Text = '' of
    true:
      begin
        ShowMessage('Campo Obligatorio');
      end;

    false:
      begin

        with DmoduloED do
        begin
          LbE.Caption := EncryptPassword(EdtPass.Text);
          LbD.Caption := DecryptPassword(LbE.Caption);
        end;
      end;
  end;

end;

end.
