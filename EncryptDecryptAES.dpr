program EncryptDecryptAES;

uses
  Vcl.Forms,
  Frm_EncryptDecryptAES in 'Frm_EncryptDecryptAES.pas' {FrmEncryptDecryptAES},
  D_moduloED in 'D_moduloED.pas' {DmoduloED: TDataModule};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFrmEncryptDecryptAES, FrmEncryptDecryptAES);
  Application.CreateForm(TDmoduloED, DmoduloED);
  Application.Run;
end.
