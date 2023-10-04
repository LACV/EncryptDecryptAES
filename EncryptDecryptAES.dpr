program EncryptDecryptAES;

uses
  Vcl.Forms,
  MEncryptDecryptAES in 'MEncryptDecryptAES.pas',
  Frm_EncryptDecryptAES in 'Frm_EncryptDecryptAES.pas' {FrmEncryptDecryptAES};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFrmEncryptDecryptAES, FrmEncryptDecryptAES);
  Application.Run;
end.
