unit MEncryptDecryptAES;

interface

uses
  System.SysUtils, System.Classes, System.Hash, System.NetEncoding,
  System.Generics.Collections, Vcl.Dialogs;

type
  TAESState = Array [0 .. 3, 0 .. 3] of Byte;
  TAESKey = Array [0 .. 7] of Cardinal;
  TAESExpandedKey = Array [0 .. 59] of Cardinal; // 59

  // Functions for encryption and decryption
function EncryptPassword(const InputPassword, Uniquekey: string): string;
function DecryptPassword(const EncryptedPassword, Uniquekey: string): string;
function EncryptHash(const InputHash, Uniquekey: string): string;
function DecryptHash(const EncryptedHash, Uniquekey: string): string;

function CalculateHash(const pass, Salt: string): string;
function verifyHash(const pass, storedSalt, storedHash: string): Boolean;

// Functions necessary for AES encryption and decryption

// Hash - SHA256(GenerateSalt)
function BytesToHex(const Bytes: TBytes): string;
function HexToUTF8(const hex: string): string;
function GenerateSalt(SaltLength: Integer): string;
function PBKDF2(const Password: string; Salt: TBytes;
  Iterations: Integer): TBytes;

// AES Encrypt (SubBytes,ShiftRows,MixColumns,AddRoundKey,BytesToHex)
procedure AESEncrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
procedure SubBytes(var State: TAESState);
procedure ShiftRows(var State: TAESState);
procedure MixColumns(var State: TAESState);
procedure InvMixColumns(var State: TAESState);
function BytesToHexArray(const Bytes: array of Byte): string;

// AES Decrypt(AESDecrypt,InvShiftRows,InvSubBytes,HexToBytes)
procedure AESDecrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
procedure InvShiftRows(var State: TAESState);
procedure InvSubBytes(var State: TAESState);
function HexToBytes(const hex: string): TBytes;

// General Use
function GenerateRandomKey(l: Integer): string;
procedure AddRoundKey(var State: TAESState; ExpandedKey: TAESExpandedKey;
  Round: Integer);
function SubWord(W: Cardinal): Cardinal;
function RotWord(W: Cardinal): Cardinal;
function RCon(n: Integer): Cardinal;
function Mult(X, Y: Byte): Byte;
function StringToAESKey(const KeyString: string): TAESKey;

procedure AESExpandKey(var ExpandedKey: TAESExpandedKey; Key: TAESKey);

implementation

const

  _Iterations = 10000; // Number of iterations

  { Lookup table used in the AES (Advanced Encryption Standard) algorithm
    for byte substitution during the SubBytes stage of encryption. This table
    contains 256 byte values in hexadecimal representation. }
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

  { Lookup table used in the AES (Advanced Encryption Standard) algorithm
    for byte substitution during the Inverse SubBytes stage of decryption.
    This table contains 256 byte values in hexadecimal representation. }
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

  { Provides a mapping between input values and output values, used to accelerate
    certain calculations or transformations in cryptographic algorithms. }
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

  { Provides a mapping between input values and output values, used to accelerate
    certain calculations or transformations in cryptographic algorithms. }
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

  {
    This function calculates a hash using the PBKDF2 algorithm with a given password
    and salt, and returns the result in hexadecimal format.
  }
function CalculateHash(const pass, Salt: string): string;
var
  Hash: THashSHA2;
  SaltBytes, hashBytes: TBytes;
begin
  // Convert the salt string to UTF-8 encoded bytes
  SaltBytes := TEncoding.UTF8.GetBytes(Salt);

  try
    // Calculate the hash using the PBKDF2 algorithm with the given password and salt
    hashBytes := PBKDF2(pass, SaltBytes, _Iterations);

    // Convert the hash bytes to a hexadecimal representation
    Result := BytesToHexArray(hashBytes);
  except
    on E: Exception do
    begin
      // Handle exceptions and provide a meaningful error message
      Result := 'Error calculating hash: ' + E.Message;
    end;
  end;
end;

{
  This function verifies a password hash by calculating a hash for the provided
  password and comparing it to a stored hash, using the stored salt.
}
function verifyHash(const pass, storedSalt, storedHash: string): Boolean;
var
  calculatedHash: string;
begin

  // Calculate the hash for the provided password and the stored salt
  calculatedHash := CalculateHash(pass, storedSalt);

  // Compare the calculated hash with the stored hash
  case calculatedHash = storedHash of
    true:
      Result := true;
    false:
      Result := false;
  end;

end;

{
  This function generates a random salt of the specified length,
  converts it to hexadecimal format, and returns it as a string.
}
function GenerateSalt(SaltLength: Integer): string;
var
  SaltBytes: TBytes;
  I: Integer;
begin
  SetLength(SaltBytes, SaltLength);

  try
    // Generate a random salt as a byte array
    for I := 0 to SaltLength - 1 do
      SaltBytes[I] := Byte(Random(256));

    // Convert the byte array using Sbox
    for I := 0 to SaltLength - 1 do
      SaltBytes[I] := Sbox[SaltBytes[I]];

    // Convert the bytes to a hexadecimal string
    Result := BytesToHex(SaltBytes);
  except
    on E: Exception do
    begin
      // Handle exceptions and provide a meaningful error message
      Result := 'Error generating salt: ' + E.Message;
    end;
  end;
end;

{
  Password-Based Key Derivation Function 2 (PBKDF2) with HMAC-SHA-256.
  This function derives a cryptographic key from a password and salt.
}
function PBKDF2(const Password: string; Salt: TBytes;
  Iterations: Integer): TBytes;
var
  HMACSHA256: THashSHA2;
  Key, InnerPad, OuterPad, SaltedPassword, U, T, DK: TBytes;
  I, J, K, DKLen: Integer;
begin
  try
    // Create an instance of the HMAC-SHA-256 hash algorithm
    HMACSHA256 := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
    // Set the desired key length (32 bytes)
    DKLen := 16;
    // Convert the password to bytes using UTF-8 encoding
    Key := TEncoding.UTF8.GetBytes(Password);

    // If the key length is greater than 64 bytes, hash it with the salt
    if Length(Key) > 64 then
    begin
      Key := HMACSHA256.GetHMACAsBytes(Key, Salt);
    end
    // If the key length is less than 64 bytes, pad it with zeros
    else if Length(Key) < 64 then
    begin
      SetLength(Key, 32);
    end;

    // Initialize inner and outer pads for HMAC computation
    InnerPad := Key;
    OuterPad := Key;
    for I := 0 to High(InnerPad) do
    begin
      InnerPad[I] := InnerPad[I] xor $36;
      OuterPad[I] := OuterPad[I] xor $5C;
    end;

    // Append an integer to the salt for the first HMAC iteration
    SetLength(Salt, Length(Salt) + SizeOf(Integer));
    // Initial HMAC computation
    T := HMACSHA256.GetHMACAsBytes(InnerPad, Salt);

    // Perform additional iterations to derive the final key
    for I := 1 to Iterations - 1 do
    begin
      U := HMACSHA256.GetHMACAsBytes(InnerPad, T);
      for J := 0 to High(U) do
      begin
        T[J] := T[J] xor U[J];
      end;
    end;

    // Copy the derived key to the result
    SetLength(DK, DKLen);
    for I := 0 to High(DK) do
    begin
      DK[I] := T[I];
    end;

    Result := DK;
  except
    on E: Exception do
    begin
      // Handle exceptions and return an empty byte array in case of an error
      Result := nil;
    end;
  end;
end;

{
  This procedure applies an XOR operation between the state and a round key in
  a cipher algorithm, adding security.
}
procedure AddRoundKey(var State: TAESState; ExpandedKey: TAESExpandedKey;
  Round: Integer);
var
  I: Integer;
  W: Cardinal;
begin
  // Apply XOR operation between state and round key
  for I := 0 to 3 do
  begin
    W := ExpandedKey[(Round * 4) + I];
    State[I, 0] := State[I, 0] XOR ((W shr 24) and $FF);
    State[I, 1] := State[I, 1] XOR ((W shr 16) and $FF);
    State[I, 2] := State[I, 2] XOR ((W shr 8) and $FF);
    State[I, 3] := State[I, 3] XOR (W and $FF);
  end;
end;

{
  This procedure performs AES decryption in 14 rounds, reversing
  the operations performed during encryption.
}
procedure AESDecrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
var
  Round: Integer;
begin
  // Perform the final round of AES decryption
  AddRoundKey(State, ExpandedKey, 14);

  // Perform the remaining rounds in reverse order
  for Round := 13 downto 1 do
  begin
    InvShiftRows(State);
    InvSubBytes(State);
    AddRoundKey(State, ExpandedKey, Round);
    InvMixColumns(State);
  end;

  // Perform the initial round
  InvShiftRows(State);
  InvSubBytes(State);
  AddRoundKey(State, ExpandedKey, 0);
end;

{
  This procedure performs AES encryption in 14 rounds, applying operations
  such as substitution, shifting, and column mixing in each round.
}
procedure AESEncrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
var
  Round: Integer;
begin
  // Perform the initial round of AES encryption
  AddRoundKey(State, ExpandedKey, 0);

  // Perform the main rounds
  for Round := 1 to 13 do
  begin
    SubBytes(State);
    ShiftRows(State);
    MixColumns(State);
    AddRoundKey(State, ExpandedKey, Round);
  end;

  // Perform the final round
  SubBytes(State);
  ShiftRows(State);
  AddRoundKey(State, ExpandedKey, 14);
end;

{
  This function expands the AES encryption key into a set of subkeys
  for use in the encryption rounds.
}
procedure AESExpandKey(var ExpandedKey: TAESExpandedKey; Key: TAESKey);
var
  I: Integer;
  Temp: Cardinal;
begin
  // Initialize the ExpandedKey with zeros
  FillChar(ExpandedKey, SizeOf(ExpandedKey), #0);

  // Copy the original key to the first 8 subkeys
  for I := 0 to 7 do
    ExpandedKey[I] := Key[I];
  // Generate additional subkeys
  for I := 8 to 59 do
  begin
    Temp := ExpandedKey[I - 1];
    if (I mod 8 = 0) then
      Temp := SubWord(RotWord(Temp)) XOR RCon(I div 8)
    else if (I mod 8 = 4) then
      Temp := SubWord(Temp);
    ExpandedKey[I] := ExpandedKey[I - 8] XOR Temp;
  end;
end;

{
  This function converts an array of bytes into a hexadecimal string.
}
function BytesToHexArray(const Bytes: array of Byte): string;
const
  HexChars: array [0 .. 15] of Char = '0123456789ABCDEF';
var
  I: Integer;
begin
  // Initialize the result string with twice the length of the input bytes
  SetLength(Result, Length(Bytes) * 2);

  // Convert each byte into a hexadecimal representation
  for I := 0 to Length(Bytes) - 1 do
  begin
    Result[I * 2 + 1] := HexChars[Bytes[I] shr 4];
    Result[I * 2 + 2] := HexChars[Bytes[I] and $0F];
  end;
end;

{
  Decrypts a password using AES with specific key and algorithm.
}
function DecryptPassword(const EncryptedPassword, Uniquekey: string): string;
var
  KeyString: string;
  Key: TAESKey;
  ExpandedKey: TAESExpandedKey;
  InputBytes, OutputBytes: TBytes;
  State: TAESState;
  SourceStream, DestStream: TMemoryStream;
begin

  // Set the key (the key should be 32 characters long)
  KeyString := Uniquekey;

  // Convert the key string to an AES key
  Key := StringToAESKey(KeyString);

  // Expand the key
  AESExpandKey(ExpandedKey, Key);

  // Convert the encrypted input string to bytes
  InputBytes := HexToBytes(EncryptedPassword);

  // Initialize the input state with zeros
  FillChar(State, SizeOf(State), 0);

  // Copy the input bytes to the state
  Move(InputBytes[0], State, Length(InputBytes));

  // Create memory streams for the result
  SourceStream := TMemoryStream.Create;
  DestStream := TMemoryStream.Create;

  try
    // Decrypt the input block
    AESDecrypt(State, ExpandedKey);
    SourceStream.Write(State, SizeOf(State));

    // Write the decrypted block to the source stream
    SourceStream.Position := 0;
    DestStream.CopyFrom(SourceStream, SourceStream.Size);

    // Convert the decrypted block to a byte array
    SetLength(OutputBytes, DestStream.Size);
    DestStream.Position := 0;
    DestStream.ReadBuffer(OutputBytes[0], DestStream.Size);
    Result := TEncoding.UTF8.GetString(OutputBytes);
  finally
    SourceStream.Free;
    DestStream.Free;
  end;

end;

function DecryptHash(const EncryptedHash, Uniquekey: string): string;
var
  KeyString: string;
  Key: TAESKey;
  ExpandedKey: TAESExpandedKey;
  InputBytes, OutputBytes: TBytes;
  State: TAESState;
  SourceStream, DestStream: TMemoryStream;
begin
  // Configurar la clave (la clave debe ser de 32 caracteres)
  KeyString := Uniquekey;

  Key := StringToAESKey(KeyString);

  // Expandir la clave
  AESExpandKey(ExpandedKey, Key);

  // Convertir el valor hexadecimal de entrada a bytes
  InputBytes := HexToBytes(EncryptedHash);

  // Asegurarse de que InputBytes tenga 64 bytes
  SetLength(InputBytes, 64);

  // Crear streams de memoria para el resultado
  SourceStream := TMemoryStream.Create;
  DestStream := TMemoryStream.Create;

  try
    // Llenar el bloque de entrada con los bytes encriptados
    FillChar(State, SizeOf(State), 0);
    Move(InputBytes[0], State, Length(InputBytes));

    // Desencriptar el bloque de entrada
    AESDecrypt(State, ExpandedKey);
    SourceStream.Write(State, SizeOf(State));

    // Copiar el bloque desencriptado al stream de destino
    SourceStream.Position := 0;
    DestStream.CopyFrom(SourceStream, SourceStream.Size);

    // Convertir el bloque desencriptado de bytes a cadena hexadecimal
    SetLength(OutputBytes, DestStream.Size);
    DestStream.Position := 0;
    DestStream.ReadBuffer(OutputBytes[0], DestStream.Size);

    Result := BytesToHexArray(OutputBytes);
  finally
    SourceStream.Free;
    DestStream.Free;
  end;
end;

{
  Encrypts a password with AES and a specific key, and returns it as hexadecimal.
}
function EncryptPassword(const InputPassword, Uniquekey: string): string;
var
  KeyString: string;
  Key: TAESKey;
  ExpandedKey: TAESExpandedKey;
  InputBytes, OutputBytes: TBytes;
  State: TAESState;
  SourceStream, DestStream: TMemoryStream;
begin

  try
    // Set the key (the key should be 32 characters long)
    KeyString := Uniquekey;

    // Convert the key string to an AES key
    Key := StringToAESKey(KeyString);

    // Expand the key
    AESExpandKey(ExpandedKey, Key);

    // Convert the input password to bytes using UTF-8 encoding
    InputBytes := TEncoding.UTF8.GetBytes(InputPassword);

    // Initialize the input state with zeros
    FillChar(State, SizeOf(State), 0);

    // Copy the input bytes to the state
    Move(InputBytes[0], State, Length(InputBytes));

    // Create memory streams for the result
    SourceStream := TMemoryStream.Create;
    DestStream := TMemoryStream.Create;

    try
      // Encriptar el bloque de entrada
      AESEncrypt(State, ExpandedKey);
      SourceStream.Write(State, SizeOf(State));

      // Copiar el bloque encriptado al stream de destino
      SourceStream.Position := 0;
      DestStream.CopyFrom(SourceStream, SourceStream.Size);

      // Convertir el bloque encriptado a una cadena hexadecimal
      SetLength(OutputBytes, DestStream.Size);
      DestStream.Position := 0;
      DestStream.ReadBuffer(OutputBytes[0], DestStream.Size);
      Result := BytesToHexArray(OutputBytes);
      // Result := BytesToHex(OutputBytes)
    finally
      SourceStream.Free;
      DestStream.Free;
    end;
  except
    on E: Exception do
    begin
      // Handle exceptions and provide a meaningful error message
      raise Exception.Create('Error in EncryptPassword: ' + E.Message);
    end;
  end;
end;

function EncryptHash(const InputHash, Uniquekey: string): string;
var
  KeyString: string;
  Key: TAESKey;
  ExpandedKey: TAESExpandedKey;
  InputBytes, OutputBytes: TBytes;
  State: TAESState;
  SourceStream, DestStream: TMemoryStream;
begin
  // Configurar la clave (la clave debe ser de 32 caracteres)
  KeyString := Uniquekey;

  Key := StringToAESKey(KeyString);

  // Expandir la clave
  AESExpandKey(ExpandedKey, Key);

  // Convertir el valor hexadecimal de entrada a bytes
  InputBytes := HexToBytes(InputHash);

  // Asegurarse de que InputBytes tenga 64 bytes
  SetLength(InputBytes, 64);

  // Crear streams de memoria para el resultado
  SourceStream := TMemoryStream.Create;
  DestStream := TMemoryStream.Create;

  try
    // Llenar el bloque de entrada con los bytes encriptados
    FillChar(State, SizeOf(State), 0);
    Move(InputBytes[0], State, Length(InputBytes));

    // Encriptar el bloque de entrada
    AESEncrypt(State, ExpandedKey);
    SourceStream.Write(State, SizeOf(State));

    // Copiar el bloque encriptado al stream de destino
    SourceStream.Position := 0;
    DestStream.CopyFrom(SourceStream, SourceStream.Size);

    // Convertir el bloque encriptado a una cadena hexadecimal de 64 caracteres
    SetLength(OutputBytes, DestStream.Size);
    DestStream.Position := 0;
    DestStream.ReadBuffer(OutputBytes[0], DestStream.Size);
    Result := BytesToHex(OutputBytes); // Cambio aquí
  finally
    SourceStream.Free;
    DestStream.Free;
  end;
end;

{
  Converts a byte array to a hexadecimal string, checking for valid length.
}
function BytesToHex(const Bytes: TBytes): string;
const
  HexChars: array [0 .. 15] of Char = '0123456789ABCDEF';
var
  I: Integer;
begin
  // Initialize the result string with twice the length of the input bytes
  SetLength(Result, Length(Bytes) * 2);

  // Convert each byte into a hexadecimal representation
  for I := 0 to Length(Bytes) - 1 do
  begin
    Result[I * 2 + 1] := HexChars[Byte(Bytes[I]) shr 4];
    Result[I * 2 + 2] := HexChars[Byte(Bytes[I]) and $F];
  end;
end;

{
  Converts a hexadecimal string to UTF-8 encoded text.
}
function HexToUTF8(const hex: string): string;
var
  I: Integer;
  hexByte: string;
  ByteValue: Byte;
  utf8Bytes: TBytes;
begin
  // Ensure that the length of the hexadecimal string is even
  if Length(hex) mod 2 <> 0 then
    raise Exception.Create('La cadena hexadecimal debe tener una longitud par');

  // Initialize a byte array with half the length of the hexadecimal string
  SetLength(utf8Bytes, Length(hex) div 2);

  for I := 1 to Length(hex) div 2 do
  begin
    // Extract two characters from the hexadecimal string
    hexByte := Copy(hex, (I - 1) * 2 + 1, 2);
    // Convert the hexadecimal byte to a Byte value
    ByteValue := StrToInt('$' + hexByte);
    utf8Bytes[I - 1] := ByteValue;
  end;

  // Convert the byte array to a UTF-8 encoded string
  Result := TEncoding.UTF8.GetString(utf8Bytes);
end;

{ Convierte cadena hexadecimal en bytes, verificando longitud válida }
function HexToBytes(const hex: string): TBytes;
var
  I: Integer;
begin
  if Length(hex) mod 2 <> 0 then
    raise Exception.Create('The hexadecimal string must have an even length');

  SetLength(Result, Length(hex) div 2);

  for I := 1 to Length(hex) div 2 do
    Result[I - 1] := StrToInt('$' + Copy(hex, (I - 1) * 2 + 1, 2));
end;

{
  This procedure reverses the "MixColumns" transformation in AES, undoing the column mixing in the state.
}
procedure InvMixColumns(var State: TAESState);
var
  I, J: Integer;
  m: Array [0 .. 3] of Byte;
begin
  for I := 0 to 3 do
  begin
    // Store the current column in a temporary array
    for J := 0 to 3 do
      // Apply the inverse MixColumns transformation
      m[J] := State[I, J];
    State[I, 0] := Mult($0E, m[0]) XOR Mult($0B, m[1]) XOR Mult($0D, m[2])
      XOR Mult($09, m[3]);
    State[I, 1] := Mult($09, m[0]) XOR Mult($0E, m[1]) XOR Mult($0B, m[2])
      XOR Mult($0D, m[3]);
    State[I, 2] := Mult($0D, m[0]) XOR Mult($09, m[1]) XOR Mult($0E, m[2])
      XOR Mult($0B, m[3]);
    State[I, 3] := Mult($0B, m[0]) XOR Mult($0D, m[1]) XOR Mult($09, m[2])
      XOR Mult($0E, m[3]);
  end;
end;

{
  This procedure performs the inverse shift of rows in the AES state.
}
procedure InvShiftRows(var State: TAESState);
var
  I, J, K: Integer;
begin
  for J := 1 to 3 do
    for I := J downto 1 do
    begin
      K := State[3, J];
      State[3, J] := State[2, J];
      State[2, J] := State[1, J];
      State[1, J] := State[0, J];
      State[0, J] := K;
    end;
end;

{
  This procedure performs the inverse byte substitution in the AES state
  using the InvSbox table.
}
procedure InvSubBytes(var State: TAESState);
var
  I, J: Integer;
begin
  for I := 0 to 3 do
    for J := 0 to 3 do
      State[I, J] := InvSbox[State[I, J]];
end;

{
  This procedure performs the MixColumns operation in AES encryption by
  multiplying each column with a specific matrix. It is part of the MixColumns
  stage in the AES encryption algorithm.
}
procedure MixColumns(var State: TAESState);
var
  I, J: Integer;
  m: Array [0 .. 3] of Byte;
begin
  for I := 0 to 3 do
  begin
    for J := 0 to 3 do
      m[J] := State[I, J];
    State[I, 0] := Mult(2, m[0]) XOR Mult(3, m[1]) XOR m[2] XOR m[3];
    State[I, 1] := m[0] XOR Mult(2, m[1]) XOR Mult(3, m[2]) XOR m[3];
    State[I, 2] := m[0] XOR m[1] XOR Mult(2, m[2]) XOR Mult(3, m[3]);
    State[I, 3] := Mult(3, m[0]) XOR m[1] XOR m[2] XOR Mult(2, m[3]);
  end;
end;

{
  This function multiplies bytes in GF(256) using LogTable and InvLogTable in AES.
}
function Mult(X, Y: Byte): Byte;
begin
  if (X = 0) or (Y = 0) then
    Result := 0
  else
    Result := InvLogTable[(LogTable[X] + LogTable[Y]) mod $FF];
end;

{
  Generates Rcon values for AES key expansion using multiplication in GF(256).
}
function RCon(n: Integer): Cardinal;
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

{
  Rotates a 32-bit word (Cardinal) 8 bits to the left.
}
function RotWord(W: Cardinal): Cardinal;
begin
  Result := (W shl 8) or (W shr 24);
end;

{
  This procedure performs a row shift operation on a state matrix in the context of the AES encryption algorithm.
  The rows of the matrix are shifted to the left in a specific pattern.
}
procedure ShiftRows(var State: TAESState);
var
  I, J, K: Integer;
begin
  for J := 1 to 3 do
    for I := J downto 1 do
    begin
      K := State[0, J];
      State[0, J] := State[1, J];
      State[1, J] := State[2, J];
      State[2, J] := State[3, J];
      State[3, J] := K;
    end;
end;

{
  Converts a text string KeyString into an AES key (TAESKey), ensuring it has a length of 32 bytes, and returns it.
}
function StringToAESKey(const KeyString: string): TAESKey;
var
  KeyBytes: TBytes;
  KeyLength: Integer;
  I: Integer;
begin
  KeyLength := Length(KeyString);
  SetLength(KeyBytes, KeyLength);

  // Convert the string into bytes
  for I := 1 to KeyLength do
    KeyBytes[I - 1] := Ord(KeyString[I]);

  // Fill the key if necessary (it should be 32 bytes)
  while Length(KeyBytes) < 32 do
    KeyBytes := KeyBytes + KeyBytes;

  // Copy the first 32 bytes as the key
  Move(KeyBytes[0], Result[0], SizeOf(Result));
end;

{
  This procedure performs the SubBytes operation on the AES state.
  It substitutes each byte in the state with its corresponding value from the Sbox.
}
procedure SubBytes(var State: TAESState);
var
  I, J: Integer;
begin
  for I := 0 to 3 do
    for J := 0 to 3 do
      State[I, J] := Sbox[State[I, J]]
end;

{
  Substitutes a 32-bit word using the AES Sbox and returns the result.
}
function SubWord(W: Cardinal): Cardinal;
begin
  // Substitute each byte of the 32-bit word using the Sbox
  Result := (Sbox[W shr 24] shl 24) or (Sbox[(W shr 16) and $FF] shl 16) or
    (Sbox[(W shr 8) and $FF] shl 8) or Sbox[W and $FF];
end;

{
  Generates a random key of the specified length and returns it as a hexadecimal string.
}
function GenerateRandomKey(l: Integer): string;
var
  KBytes: TBytes;
  I: Integer;
begin

  SetLength(KBytes, l);

  // Generate a random salt as a byte array
  for I := 0 to l - 1 do
    KBytes[I] := Byte(Random(256));

  // Substitute each byte of the salt using the Sbox
  for I := 0 to l - 1 do
    KBytes[I] := Sbox[KBytes[I]];

  // Convert the bytes to a hexadecimal string
  Result := BytesToHex(KBytes);
end;

end.
