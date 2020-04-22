
SET PROTOC_PATH="C:/Users/malachi/Documents/Projects/Targaryen/protoc-3.3.0-win32/bin/protoc.exe"

SET OUT_DIR="C:/Users/malachi/Documents/Projects/Targaryen/targaryen/Disassembly"

SET SRC_DIR="C:/Users/malachi/Documents/Projects/Targaryen/targaryen/Disassembly/"

%PROTOC_PATH% -I=%SRC_DIR%  --python_out=%OUT_DIR% %SRC_DIR%/disassembly.proto

pause