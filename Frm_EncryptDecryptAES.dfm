object FrmEncryptDecryptAES: TFrmEncryptDecryptAES
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = 'FrmEncryptDecryptAES'
  ClientHeight = 609
  ClientWidth = 749
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  PixelsPerInch = 96
  TextHeight = 13
  object PnInferior: TPanel
    Left = 0
    Top = 0
    Width = 749
    Height = 609
    Align = alClient
    TabOrder = 0
    object LbVerificacion: TLabel
      AlignWithMargins = True
      Left = 31
      Top = 573
      Width = 120
      Height = 24
      Margins.Left = 30
      Margins.Top = 15
      Margins.Right = 5
      Margins.Bottom = 10
      Align = alLeft
      Alignment = taRightJustify
      Caption = 'Verificacion'
      Enabled = False
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clMaroon
      Font.Height = -20
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
      WordWrap = True
    end
    object BtnValidar: TButton
      AlignWithMargins = True
      Left = 31
      Top = 65
      Width = 687
      Height = 47
      Margins.Left = 30
      Margins.Top = 15
      Margins.Right = 30
      Margins.Bottom = 10
      Align = alTop
      Caption = '&Validar'
      Font.Charset = ANSI_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ImageIndex = 5
      ImageMargins.Left = 2
      ParentFont = False
      ParentShowHint = False
      ShowHint = False
      TabOrder = 0
      OnClick = BtnValidarClick
    end
    object EdtPass: TEdit
      AlignWithMargins = True
      Left = 31
      Top = 16
      Width = 687
      Height = 24
      Margins.Left = 30
      Margins.Top = 15
      Margins.Right = 30
      Margins.Bottom = 10
      Align = alTop
      CharCase = ecUpperCase
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -13
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
      TabOrder = 1
      Text = 'LACV123'
      TextHint = 'Digitar Pass'
    end
    object Panel1: TPanel
      Left = 1
      Top = 302
      Width = 747
      Height = 45
      Align = alTop
      BevelOuter = bvNone
      TabOrder = 2
      object Label1: TLabel
        AlignWithMargins = True
        Left = 30
        Top = 15
        Width = 95
        Height = 18
        Margins.Left = 30
        Margins.Top = 15
        Margins.Right = 5
        Margins.Bottom = 10
        Align = alLeft
        Alignment = taRightJustify
        Caption = 'AES Encrypt:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clBlack
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
      object EdtEncrypt: TEdit
        AlignWithMargins = True
        Left = 133
        Top = 3
        Width = 611
        Height = 39
        Align = alClient
        TabOrder = 0
        ExplicitHeight = 21
      end
    end
    object Panel2: TPanel
      Left = 1
      Top = 122
      Width = 747
      Height = 45
      Align = alTop
      BevelOuter = bvNone
      TabOrder = 3
      object Label3: TLabel
        AlignWithMargins = True
        Left = 30
        Top = 15
        Width = 92
        Height = 18
        Margins.Left = 30
        Margins.Top = 15
        Margins.Right = 5
        Margins.Bottom = 10
        Align = alLeft
        Alignment = taRightJustify
        Caption = 'Dato Inicial:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clBlack
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
      object LbD: TLabel
        AlignWithMargins = True
        Left = 177
        Top = 15
        Width = 11
        Height = 18
        Margins.Left = 50
        Margins.Top = 15
        Margins.Right = 30
        Margins.Bottom = 10
        Align = alLeft
        Caption = 'D'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clHotLight
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
    end
    object Panel3: TPanel
      Left = 1
      Top = 212
      Width = 747
      Height = 45
      Align = alTop
      BevelOuter = bvNone
      TabOrder = 4
      object Label4: TLabel
        AlignWithMargins = True
        Left = 30
        Top = 15
        Width = 66
        Height = 18
        Margins.Left = 30
        Margins.Top = 15
        Margins.Right = 5
        Margins.Bottom = 10
        Align = alLeft
        Caption = 'SHA256:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clBlack
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
      object EdtSha: TEdit
        AlignWithMargins = True
        Left = 104
        Top = 3
        Width = 640
        Height = 39
        Align = alClient
        TabOrder = 0
        ExplicitHeight = 21
      end
    end
    object Panel4: TPanel
      Left = 1
      Top = 257
      Width = 747
      Height = 45
      Align = alTop
      BevelOuter = bvNone
      TabOrder = 5
      object Label5: TLabel
        AlignWithMargins = True
        Left = 30
        Top = 15
        Width = 79
        Height = 18
        Margins.Left = 30
        Margins.Top = 15
        Margins.Right = 5
        Margins.Bottom = 10
        Align = alLeft
        Alignment = taRightJustify
        Caption = 'Key Unica:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clBlack
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
      object EdtKey: TEdit
        AlignWithMargins = True
        Left = 117
        Top = 3
        Width = 627
        Height = 39
        Align = alClient
        TabOrder = 0
        ExplicitHeight = 21
      end
    end
    object Panel5: TPanel
      Left = 1
      Top = 347
      Width = 747
      Height = 45
      Align = alTop
      BevelOuter = bvNone
      TabOrder = 6
      object Label6: TLabel
        AlignWithMargins = True
        Left = 30
        Top = 15
        Width = 97
        Height = 18
        Margins.Left = 30
        Margins.Top = 15
        Margins.Right = 5
        Margins.Bottom = 10
        Align = alLeft
        Alignment = taRightJustify
        Caption = 'AES Decrypt:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clBlack
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
      object EdtDecrypt: TEdit
        AlignWithMargins = True
        Left = 135
        Top = 3
        Width = 609
        Height = 39
        Align = alClient
        TabOrder = 0
        ExplicitHeight = 21
      end
    end
    object Panel7: TPanel
      Left = 1
      Top = 167
      Width = 747
      Height = 45
      Align = alTop
      BevelOuter = bvNone
      TabOrder = 7
      object Label7: TLabel
        AlignWithMargins = True
        Left = 30
        Top = 15
        Width = 35
        Height = 18
        Margins.Left = 30
        Margins.Top = 15
        Margins.Right = 5
        Margins.Bottom = 10
        Align = alLeft
        Alignment = taRightJustify
        Caption = 'Salt:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clBlack
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
      object EdtSalt: TEdit
        AlignWithMargins = True
        Left = 73
        Top = 3
        Width = 671
        Height = 39
        Align = alClient
        TabOrder = 0
        ExplicitHeight = 21
      end
    end
    object Panel6: TPanel
      Left = 1
      Top = 513
      Width = 747
      Height = 45
      Align = alTop
      BevelOuter = bvNone
      TabOrder = 8
      object Label2: TLabel
        AlignWithMargins = True
        Left = 30
        Top = 15
        Width = 61
        Height = 18
        Margins.Left = 30
        Margins.Top = 15
        Margins.Right = 5
        Margins.Bottom = 10
        Align = alLeft
        Alignment = taRightJustify
        Caption = 'SHA256'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clBlack
        Font.Height = -15
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        WordWrap = True
      end
      object EdtSha2: TEdit
        AlignWithMargins = True
        Left = 99
        Top = 3
        Width = 645
        Height = 39
        Align = alClient
        Enabled = False
        TabOrder = 0
        ExplicitHeight = 21
      end
    end
    object BtnComparar: TButton
      AlignWithMargins = True
      Left = 31
      Top = 456
      Width = 687
      Height = 47
      Margins.Left = 30
      Margins.Top = 15
      Margins.Right = 30
      Margins.Bottom = 10
      Align = alTop
      Caption = '&Comparar'
      Enabled = False
      Font.Charset = ANSI_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ImageIndex = 5
      ImageMargins.Left = 2
      ParentFont = False
      ParentShowHint = False
      ShowHint = False
      TabOrder = 9
      OnClick = BtnCompararClick
    end
    object EdtPass2: TEdit
      AlignWithMargins = True
      Left = 31
      Top = 407
      Width = 687
      Height = 24
      Margins.Left = 30
      Margins.Top = 15
      Margins.Right = 30
      Margins.Bottom = 10
      Align = alTop
      CharCase = ecUpperCase
      Enabled = False
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -13
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
      TabOrder = 10
      Text = 'LACV123'
      TextHint = 'Digitar Pass'
    end
  end
end
