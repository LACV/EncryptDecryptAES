unit D_moduloED;

interface

uses
  System.SysUtils, System.Classes;

type
  TAESState = Array [0 .. 3, 0 .. 3] of Byte;
  TAESKey = Array [0 .. 7] of Cardinal;
  TAESExpandedKey = Array [0 .. 59] of Cardinal;

type
  TDmoduloED = class(TDataModule)
  private
    function BytesToHex(const Bytes: array of Byte): string;
    { Private declarations }
  public
    { Public declarations }
    // funciones para encriptar y desencriptar
    function EncryptPassword(const InputPassword: string): string;
    function DecryptPassword(const EncryptedPassword: string): string;

    // funciones necesarias para encriptar y desencriptar en AES

    // AES Encrypt (SubBytes,ShiftRows,MixColumns,AddRoundKey,BytesToHex)
    procedure AESEncrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
    procedure SubBytes(var State: TAESState);
    procedure ShiftRows(var State: TAESState);
    procedure MixColumns(var State: TAESState);
    procedure InvMixColumns(var State: TAESState);

    // AES Decrypt(AESDecrypt,InvShiftRows,InvSubBytes,HexToBytes)
    procedure AESDecrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
    procedure InvShiftRows(var State: TAESState);
    procedure InvSubBytes(var State: TAESState);
    function HexToBytes(const Hex: string): TBytes;

    // Uso General
    procedure AddRoundKey(var State: TAESState; ExpandedKey: TAESExpandedKey;
      Round: Integer);
    function SubWord(W: Cardinal): Cardinal;
    function RotWord(W: Cardinal): Cardinal;
    function RCon(n: Integer): Cardinal;
    function Mult(X, Y: Byte): Byte;
    function StringToAESKey(const KeyString: string): TAESKey;

    procedure AESExpandKey(var ExpandedKey: TAESExpandedKey; Key: TAESKey);
  end;

var
  DmoduloED: TDmoduloED;

implementation

const
  { tabla de búsqueda utiliza  el algoritmo AES (Advanced Encryption Standard)
    para la sustitución de bytes durante la etapa de sustitución de SubBytes en la
    encriptación. Esta tabla contiene 256 valores de bytes en representación hexadecimal }
  Sbox: Array [0 .. 255] of Byte = ($63, $7C, $77, $7B, $F2, $6B, $6F, $C5, $30,
    $01, $67, $2B, $FE, $D7, $AB, $76, $CA, $82, $C9, $7D, $FA, $59, $47, $F0,
    $AD, $D4, $A2, $AF, $9C, $A4, $72, $C0, $B7, $FD, $93, $26, $36, $3F, $F7,
    $CC, $34, $A5, $E5, $F1, $71, $D8, $31, $15, $04, $C7, $23, $C3, $18, $96,
    $05, $9A, $07, $12, $80, $E2, $EB, $27, $B2, $75, $09, $83, $2C, $1A, $1B,
    $6E, $5A, $A0, $52, $3B, $D6, $B3, $29, $E3, $2F, $84, $53, $D1, $00, $ED,
    $20, $FC, $B1, $5B, $6A, $CB, $BE, $39, $4A, $4C, $58, $CF, $D0, $EF, $AA,
    $FB, $43, $4D, $33, $85, $45, $F9, $02, $7F, $50, $3C, $9F, $A8, $51, $A3,
    $40, $8F, $92, $9D, $38, $F5, $BC, $B6, $DA, $21, $10, $FF, $F3, $D2, $CD,
    $0C, $13, $EC, $5F, $97, $44, $17, $C4, $A7, $7E, $3D, $64, $5D, $19, $73,
    $60, $81, $4F, $DC, $22, $2A, $90, $88, $46, $EE, $B8, $14, $DE, $5E, $0B,
    $DB, $E0, $32, $3A, $0A, $49, $06, $24, $5C, $C2, $D3, $AC, $62, $91, $95,
    $E4, $79, $E7, $C8, $37, $6D, $8D, $D5, $4E, $A9, $6C, $56, $F4, $EA, $65,
    $7A, $AE, $08, $BA, $78, $25, $2E, $1C, $A6, $B4, $C6, $E8, $DD, $74, $1F,
    $4B, $BD, $8B, $8A, $70, $3E, $B5, $66, $48, $03, $F6, $0E, $61, $35, $57,
    $B9, $86, $C1, $1D, $9E, $E1, $F8, $98, $11, $69, $D9, $8E, $94, $9B, $1E,
    $87, $E9, $CE, $55, $28, $DF, $8C, $A1, $89, $0D, $BF, $E6, $42, $68, $41,
    $99, $2D, $0F, $B0, $54, $BB, $16);

  { tabla de búsqueda utilizada en el algoritmo AES (Advanced Encryption Standard)
    para la sustitución inversa de bytes durante la etapa de sustitución de InvSubBytes
    en el proceso de desencriptación. Esta tabla contiene 256 valores de bytes en
    representación hexadecimal }
  InvSbox: Array [0 .. 255] of Byte = ($52, $09, $6A, $D5, $30, $36, $A5, $38,
    $BF, $40, $A3, $9E, $81, $F3, $D7, $FB, $7C, $E3, $39, $82, $9B, $2F, $FF,
    $87, $34, $8E, $43, $44, $C4, $DE, $E9, $CB, $54, $7B, $94, $32, $A6, $C2,
    $23, $3D, $EE, $4C, $95, $0B, $42, $FA, $C3, $4E, $08, $2E, $A1, $66, $28,
    $D9, $24, $B2, $76, $5B, $A2, $49, $6D, $8B, $D1, $25, $72, $F8, $F6, $64,
    $86, $68, $98, $16, $D4, $A4, $5C, $CC, $5D, $65, $B6, $92, $6C, $70, $48,
    $50, $FD, $ED, $B9, $DA, $5E, $15, $46, $57, $A7, $8D, $9D, $84, $90, $D8,
    $AB, $00, $8C, $BC, $D3, $0A, $F7, $E4, $58, $05, $B8, $B3, $45, $06, $D0,
    $2C, $1E, $8F, $CA, $3F, $0F, $02, $C1, $AF, $BD, $03, $01, $13, $8A, $6B,
    $3A, $91, $11, $41, $4F, $67, $DC, $EA, $97, $F2, $CF, $CE, $F0, $B4, $E6,
    $73, $96, $AC, $74, $22, $E7, $AD, $35, $85, $E2, $F9, $37, $E8, $1C, $75,
    $DF, $6E, $47, $F1, $1A, $71, $1D, $29, $C5, $89, $6F, $B7, $62, $0E, $AA,
    $18, $BE, $1B, $FC, $56, $3E, $4B, $C6, $D2, $79, $20, $9A, $DB, $C0, $FE,
    $78, $CD, $5A, $F4, $1F, $DD, $A8, $33, $88, $07, $C7, $31, $B1, $12, $10,
    $59, $27, $80, $EC, $5F, $60, $51, $7F, $A9, $19, $B5, $4A, $0D, $2D, $E5,
    $7A, $9F, $93, $C9, $9C, $EF, $A0, $E0, $3B, $4D, $AE, $2A, $F5, $B0, $C8,
    $EB, $BB, $3C, $83, $53, $99, $61, $17, $2B, $04, $7E, $BA, $77, $D6, $26,
    $E1, $69, $14, $63, $55, $21, $0C, $7D);

  { Proporciona una correspondencia entre valores de entrada y valores de salida,
    se utilizan para acelerar ciertos cálculos o transformaciones en algoritmos
    criptográficos }
  InvLogTable: Array [0 .. 255] of Byte = ($01, $E5, $4C, $B5, $FB, $9F, $FC,
    $12, $03, $34, $D4, $C4, $16, $BA, $1F, $36, $05, $5C, $67, $57, $3A, $D5,
    $21, $5A, $0F, $E4, $A9, $F9, $4E, $64, $63, $EE, $11, $37, $E0, $10, $D2,
    $AC, $A5, $29, $33, $59, $3B, $30, $6D, $EF, $F4, $7B, $55, $EB, $4D, $50,
    $B7, $2A, $07, $8D, $FF, $26, $D7, $F0, $C2, $7E, $09, $8C, $1A, $6A, $62,
    $0B, $5D, $82, $1B, $8F, $2E, $BE, $A6, $1D, $E7, $9D, $2D, $8A, $72, $D9,
    $F1, $27, $32, $BC, $77, $85, $96, $70, $08, $69, $56, $DF, $99, $94, $A1,
    $90, $18, $BB, $FA, $7A, $B0, $A7, $F8, $AB, $28, $D6, $15, $8E, $CB, $F2,
    $13, $E6, $78, $61, $3F, $89, $46, $0D, $35, $31, $88, $A3, $41, $80, $CA,
    $17, $5F, $53, $83, $FE, $C3, $9B, $45, $39, $E1, $F5, $9E, $19, $5E, $B6,
    $CF, $4B, $38, $04, $B9, $2B, $E2, $C1, $4A, $DD, $48, $0C, $D0, $7D, $3D,
    $58, $DE, $7C, $D8, $14, $6B, $87, $47, $E8, $79, $84, $73, $3C, $BD, $92,
    $C9, $23, $8B, $97, $95, $44, $DC, $AD, $40, $65, $86, $A2, $A4, $CC, $7F,
    $EC, $C0, $AF, $91, $FD, $F7, $4F, $81, $2F, $5B, $EA, $A8, $1C, $02, $D1,
    $98, $71, $ED, $25, $E3, $24, $06, $68, $B3, $93, $2C, $6F, $3E, $6C, $0A,
    $B8, $CE, $AE, $74, $B1, $42, $B4, $1E, $D3, $49, $E9, $9C, $C8, $C6, $C7,
    $22, $6E, $DB, $20, $BF, $43, $51, $52, $66, $B2, $76, $60, $DA, $C5, $F3,
    $F6, $AA, $CD, $9A, $A0, $75, $54, $0E, $01);

  { Proporciona una correspondencia entre valores de entrada y valores de salida,
    se utilizan para acelerar ciertos cálculos o transformaciones en algoritmos
    criptográficos }
  LogTable: Array [0 .. 255] of Byte = ($00, $FF, $C8, $08, $91, $10, $D0, $36,
    $5A, $3E, $D8, $43, $99, $77, $FE, $18, $23, $20, $07, $70, $A1, $6C, $0C,
    $7F, $62, $8B, $40, $46, $C7, $4B, $E0, $0E, $EB, $16, $E8, $AD, $CF, $CD,
    $39, $53, $6A, $27, $35, $93, $D4, $4E, $48, $C3, $2B, $79, $54, $28, $09,
    $78, $0F, $21, $90, $87, $14, $2A, $A9, $9C, $D6, $74, $B4, $7C, $DE, $ED,
    $B1, $86, $76, $A4, $98, $E2, $96, $8F, $02, $32, $1C, $C1, $33, $EE, $EF,
    $81, $FD, $30, $5C, $13, $9D, $29, $17, $C4, $11, $44, $8C, $80, $F3, $73,
    $42, $1E, $1D, $B5, $F0, $12, $D1, $5B, $41, $A2, $D7, $2C, $E9, $D5, $59,
    $CB, $50, $A8, $DC, $FC, $F2, $56, $72, $A6, $65, $2F, $9F, $9B, $3D, $BA,
    $7D, $C2, $45, $82, $A7, $57, $B6, $A3, $7A, $75, $4F, $AE, $3F, $37, $6D,
    $47, $61, $BE, $AB, $D3, $5F, $B0, $58, $AF, $CA, $5E, $FA, $85, $E4, $4D,
    $8A, $05, $FB, $60, $B7, $7B, $B8, $26, $4A, $67, $C6, $1A, $F8, $69, $25,
    $B3, $DB, $BD, $66, $DD, $F1, $D2, $DF, $03, $8D, $34, $D9, $92, $0D, $63,
    $55, $AA, $49, $EC, $BC, $95, $3C, $84, $0B, $F5, $E6, $E7, $E5, $AC, $7E,
    $6E, $B9, $F9, $DA, $8E, $9A, $C9, $24, $E1, $0A, $15, $6B, $3A, $A0, $51,
    $F4, $EA, $B2, $97, $9E, $5D, $22, $88, $94, $CE, $19, $01, $71, $4C, $A5,
    $E3, $C5, $31, $BB, $CC, $1F, $2D, $3B, $52, $6F, $F6, $2E, $89, $F7, $C0,
    $68, $1B, $64, $04, $06, $BF, $83, $38);

{%CLASSGROUP 'Vcl.Controls.TControl'}
{$R *.dfm}

  { Este procedimiento aplica una operación XOR entre el estado y una clave de
    ronda en un algoritmo de cifrado, añadiendo seguridad. }
procedure TDmoduloED.AddRoundKey(var State: TAESState;
  ExpandedKey: TAESExpandedKey; Round: Integer);
var
  i: Integer;
  W: Cardinal;
begin

  for i := 0 to 3 do
  begin
    W := ExpandedKey[(Round * 4) + i];
    State[i, 0] := State[i, 0] XOR ((W shr 24) and $FF);
    State[i, 1] := State[i, 1] XOR ((W shr 16) and $FF);
    State[i, 2] := State[i, 2] XOR ((W shr 8) and $FF);
    State[i, 3] := State[i, 3] XOR (W and $FF);
  end;
end;

{ Este procedimiento realiza la desencriptación AES en 14 rondas, invirtiendo
  las operaciones realizadas en la encriptación }
procedure TDmoduloED.AESDecrypt(var State: TAESState;
  ExpandedKey: TAESExpandedKey);
var
  Round: Integer;
begin

  AddRoundKey(State, ExpandedKey, 14);
  for Round := 13 downto 1 do
  begin
    InvShiftRows(State);
    InvSubBytes(State);
    AddRoundKey(State, ExpandedKey, Round);
    InvMixColumns(State);
  end;
  InvShiftRows(State);
  InvSubBytes(State);
  AddRoundKey(State, ExpandedKey, 0);
end;

{ Este procedimiento realiza la encriptación AES en 14 rondas, aplicando
  operaciones como sustitución, desplazamiento y mezcla de columnas en
  cada ronda }
procedure TDmoduloED.AESEncrypt(var State: TAESState;
  ExpandedKey: TAESExpandedKey);
var
  Round: Integer;
begin
  AddRoundKey(State, ExpandedKey, 0);
  for Round := 1 to 13 do
  begin
    SubBytes(State);
    ShiftRows(State);
    MixColumns(State);
    AddRoundKey(State, ExpandedKey, Round);
  end;
  SubBytes(State);
  ShiftRows(State);
  AddRoundKey(State, ExpandedKey, 14);
end;

{ Esta función expande la clave de cifrado AES en un conjunto de subclaves
  para su uso en las rondas de cifrado }
procedure TDmoduloED.AESExpandKey(var ExpandedKey: TAESExpandedKey;
  Key: TAESKey);
var
  i: Integer;
  Temp: Cardinal;
begin

  FillChar(ExpandedKey, Sizeof(ExpandedKey), #0);
  for i := 0 to 7 do
    ExpandedKey[i] := Key[i];
  for i := 8 to 59 do
  begin
    Temp := ExpandedKey[i - 1];
    if (i mod 8 = 0) then
      Temp := SubWord(RotWord(Temp)) XOR RCon(i div 8)
    else if (i mod 8 = 4) then
      Temp := SubWord(Temp);
    ExpandedKey[i] := ExpandedKey[i - 8] XOR Temp;
  end;
end;

{ Esta función convierte un array de bytes en una cadena hexadecimal }
function TDmoduloED.BytesToHex(const Bytes: array of Byte): string;
const
  HexChars: array [0 .. 15] of Char = '0123456789ABCDEF';
var
  i: Integer;
begin

  SetLength(Result, Length(Bytes) * 2);
  for i := 0 to Length(Bytes) - 1 do
  begin
    Result[i * 2 + 1] := HexChars[Bytes[i] shr 4];
    Result[i * 2 + 2] := HexChars[Bytes[i] and $0F];
  end;
end;

{ Desencripta contraseña usando AES con clave y algoritmo específicos }
function TDmoduloED.DecryptPassword(const EncryptedPassword: string): string;
var
  ModuloED: TDmoduloED;
  KeyString: string;
  Key: TAESKey;
  ExpandedKey: TAESExpandedKey;
  InputBytes, OutputBytes: TBytes;
  State: TAESState;
  SourceStream, DestStream: TMemoryStream;
begin

  try
    // Configurar la clave (la clave debe ser de 32 caracteres)
    KeyString := 'ArrozBolugaLoMejorEnsuMesa';
    Key := StringToAESKey(KeyString);

    // Expandir la clave
    ModuloED.AESExpandKey(ExpandedKey, Key);

    // Convertir la cadena encriptada de entrada a bytes
    InputBytes := HexToBytes(EncryptedPassword);

    // Rellenar el bloque de entrada
    FillChar(State, Sizeof(State), 0);
    Move(InputBytes[0], State, Length(InputBytes));

    // Crear streams de memoria para el resultado
    SourceStream := TMemoryStream.Create;
    DestStream := TMemoryStream.Create;

    try
      // Desencriptar el bloque de entrada
      ModuloED.AESDecrypt(State, ExpandedKey);
      SourceStream.Write(State, Sizeof(State));

      // Copiar el bloque desencriptado al stream de destino
      SourceStream.Position := 0;
      DestStream.CopyFrom(SourceStream, SourceStream.Size);

      // Convertir el bloque desencriptado a una cadena de texto
      SetLength(OutputBytes, DestStream.Size);
      DestStream.Position := 0;
      DestStream.ReadBuffer(OutputBytes[0], DestStream.Size);
      Result := TEncoding.UTF8.GetString(OutputBytes);
    finally
      SourceStream.Free;
      DestStream.Free;
    end;
  finally

  end;
end;

{ Encripta contraseña con AES y clave específica, devuelve como hexadecimal }
function TDmoduloED.EncryptPassword(const InputPassword: string): string;
var
  ModuloED: TDmoduloED;
  KeyString: string;
  Key: TAESKey;
  ExpandedKey: TAESExpandedKey;
  InputBytes, OutputBytes: TBytes;
  State: TAESState;
  SourceStream, DestStream: TMemoryStream;
begin
  // Crear una instancia de TDmoduloED
  // ModuloED := TDmoduloED.Create(nil);

  try
    // Configurar la clave (la clave debe ser de 32 caracteres)
    KeyString := 'ArrozBolugaLoMejorEnsuMesa';
    Key := StringToAESKey(KeyString);

    // Expandir la clave
    ModuloED.AESExpandKey(ExpandedKey, Key);

    // Convertir la contraseña de entrada a bytes
    InputBytes := TEncoding.UTF8.GetBytes(InputPassword);

    // Rellenar el bloque de entrada
    FillChar(State, Sizeof(State), 0);
    Move(InputBytes[0], State, Length(InputBytes));

    // Crear streams de memoria para el resultado
    SourceStream := TMemoryStream.Create;
    DestStream := TMemoryStream.Create;

    try
      // Encriptar el bloque de entrada
      ModuloED.AESEncrypt(State, ExpandedKey);
      SourceStream.Write(State, Sizeof(State));

      // Copiar el bloque encriptado al stream de destino
      SourceStream.Position := 0;
      DestStream.CopyFrom(SourceStream, SourceStream.Size);

      // Convertir el bloque encriptado a una cadena hexadecimal
      SetLength(OutputBytes, DestStream.Size);
      DestStream.Position := 0;
      DestStream.ReadBuffer(OutputBytes[0], DestStream.Size);
      Result := BytesToHex(OutputBytes);
    finally
      SourceStream.Free;
      DestStream.Free;
    end;
  finally
    // ModuloED.Free;
  end;
end;

{ Convierte cadena hexadecimal en bytes, verificando longitud válida }
function TDmoduloED.HexToBytes(const Hex: string): TBytes;
var
  i: Integer;
begin
  if Length(Hex) mod 2 <> 0 then
    raise Exception.Create('Longitud de cadena hexadecimal no válida');

  SetLength(Result, Length(Hex) div 2);

  for i := 1 to Length(Hex) div 2 do
    Result[i - 1] := StrToInt('$' + Copy(Hex, (i - 1) * 2 + 1, 2));
end;

{ Este procedimiento deshace la transformación "MixColumns" en AES, revirtiendo
  la mezcla de columnas en el estado }
procedure TDmoduloED.InvMixColumns(var State: TAESState);
var
  i, j: Integer;
  m: Array [0 .. 3] of Byte;
begin
  for i := 0 to 3 do
  begin
    for j := 0 to 3 do
      m[j] := State[i, j];
    State[i, 0] := Mult($0E, m[0]) XOR Mult($0B, m[1]) XOR Mult($0D, m[2])
      XOR Mult($09, m[3]);
    State[i, 1] := Mult($09, m[0]) XOR Mult($0E, m[1]) XOR Mult($0B, m[2])
      XOR Mult($0D, m[3]);
    State[i, 2] := Mult($0D, m[0]) XOR Mult($09, m[1]) XOR Mult($0E, m[2])
      XOR Mult($0B, m[3]);
    State[i, 3] := Mult($0B, m[0]) XOR Mult($0D, m[1]) XOR Mult($09, m[2])
      XOR Mult($0E, m[3]);
  end;
end;

{ Este procedimiento realiza el desplazamiento inverso de las filas en el
  estado en el algoritmo AES }
procedure TDmoduloED.InvShiftRows(var State: TAESState);
var
  i, j, k: Integer;
begin
  for j := 1 to 3 do
    for i := j downto 1 do
    begin
      k := State[3, j];
      State[3, j] := State[2, j];
      State[2, j] := State[1, j];
      State[1, j] := State[0, j];
      State[0, j] := k;
    end;
end;

{ Este procedimiento realiza la sustitución inversa de bytes en el estado
  utilizando la tabla InvSbox en el algoritmo AES }
procedure TDmoduloED.InvSubBytes(var State: TAESState);
var
  i, j: Integer;
begin
  for i := 0 to 3 do
    for j := 0 to 3 do
      State[i, j] := InvSbox[State[i, j]];
end;

{ Este procedimiento realiza la operación de mezcla de columnas en el estado
  del cifrado AES, multiplicando cada columna por una matriz específica. Es
  parte del proceso de mezcla de columnas en la etapa de cifrado del algoritmo
  AES }
procedure TDmoduloED.MixColumns(var State: TAESState);
var
  i, j: Integer;
  m: Array [0 .. 3] of Byte;
begin
  for i := 0 to 3 do
  begin
    for j := 0 to 3 do
      m[j] := State[i, j];
    State[i, 0] := Mult(2, m[0]) XOR Mult(3, m[1]) XOR m[2] XOR m[3];
    State[i, 1] := m[0] XOR Mult(2, m[1]) XOR Mult(3, m[2]) XOR m[3];
    State[i, 2] := m[0] XOR m[1] XOR Mult(2, m[2]) XOR Mult(3, m[3]);
    State[i, 3] := Mult(3, m[0]) XOR m[1] XOR m[2] XOR Mult(2, m[3]);
  end;
end;

{ Mult multiplica bytes en GF(256) usando LogTable e InvLogTable en AES. }
function TDmoduloED.Mult(X, Y: Byte): Byte;
begin
  if (X = 0) or (Y = 0) then
    Result := 0
  else
    Result := InvLogTable[(LogTable[X] + LogTable[Y]) mod $FF];
end;

{ Genera valores Rcon para expandir claves AES usando multiplicación en GF(256) }
function TDmoduloED.RCon(n: Integer): Cardinal;
begin
  Result := 1;
  if n = 0 then
    Result := 0
  else
    while n > 1 do
    begin
      Result := Mult(Result, 2);
      dec(n);
    end;
  Result := Result shl 24;
end;

{ Rota una palabra de 32 bits (Cardinal) 8 bits hacia la izquierda }
function TDmoduloED.RotWord(W: Cardinal): Cardinal;
begin
  Result := (W shl 8) or (W shr 24);
end;

{ Esta función realiza un desplazamiento de filas en una matriz de estado
  en el contexto del algoritmo de cifrado AES. Las filas de la matriz se
  desplazan hacia la izquierda en un patrón específico }
procedure TDmoduloED.ShiftRows(var State: TAESState);
var
  i, j, k: Integer;
begin
  for j := 1 to 3 do
    for i := j downto 1 do
    begin
      k := State[0, j];
      State[0, j] := State[1, j];
      State[1, j] := State[2, j];
      State[2, j] := State[3, j];
      State[3, j] := k;
    end;
end;

function TDmoduloED.StringToAESKey(const KeyString: string): TAESKey;
var
  KeyBytes: TBytes;
  KeyLength: Integer;
  i: Integer;
begin
  KeyLength := Length(KeyString);
  SetLength(KeyBytes, KeyLength);

  // Convertir el string en bytes
  for i := 1 to KeyLength do
    KeyBytes[i - 1] := Ord(KeyString[i]);

  // Rellenar la clave si es necesario (debe ser de 32 bytes)
  while Length(KeyBytes) < 32 do
    KeyBytes := KeyBytes + KeyBytes;

  // Copiar los primeros 32 bytes como clave
  Move(KeyBytes[0], Result[0], Sizeof(Result));
end;

{Esta función toma una cadena de texto KeyString, la convierte en una clave
AES (TAESKey), asegurándose de que la clave tenga una longitud de 32 bytes y
luego la devuelve como resultado}
procedure TDmoduloED.SubBytes(var State: TAESState);
var
  i, j: Integer;
begin
  for i := 0 to 3 do
    for j := 0 to 3 do
      State[i, j] := Sbox[State[i, j]]
end;

{Sustituye una palabra de 32 bits con Sbox de AES y retorna el resultado}
function TDmoduloED.SubWord(W: Cardinal): Cardinal;
begin
  Result := (Sbox[W shr 24] shl 24) or (Sbox[(W shr 16) and $FF] shl 16) or
    (Sbox[(W shr 8) and $FF] shl 8) or Sbox[W and $FF];
end;

end.
