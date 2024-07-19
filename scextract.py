import sys
import re

def xor_encrypt(data, key):
    encrypted_data = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % key_len])
    return encrypted_data

def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            pattern = r"\b(?:mov|movsxd|ret|cmp|lea|call|inc|jmp|movzx|push|nop|ret|xor|sub|pop|jb|add|je|test|imul|jne|ja|jae|movzx|movdqu|movdqa|rep stos)\b.*"
            replace = ""
            content = re.sub(pattern, replace, content)
            pattern = r" "
            replace = ""
            content = re.sub(pattern, replace, content)
            pattern = r"\n"
            replace = ""
            content = re.sub(pattern, replace, content)
            pattern = r"(.{30})"
            replace = r"\g<0>\n"
            content = re.sub(pattern, replace, content)
            pattern = r"(.{2})"
            replace = r"\\x\1"
            content = re.sub(pattern, replace, content)
            pattern = r"(^|$)"
            replace = r'"'
            content = re.sub(pattern, replace, content, flags=re.MULTILINE)

            # Convert shellcode string to bytes
            shellcode_str = content.replace('\\x', '').replace('"', '')
            shellcode_bytes = bytes.fromhex(shellcode_str)
            return shellcode_bytes, None  # Return tuple (shellcode_bytes, None)
    except FileNotFoundError:
        return None, f"file '{file_path}' not found."
    except Exception as e:
        return None, f"Cannot read file because: {str(e)}"

def format_shellcode(shellcode_bytes):
    encrypted_shellcode = ''.join(f'\\x{byte:02x}' for byte in shellcode_bytes)

    # Split into lines of 30 bytes each
    formatted_lines = [encrypted_shellcode[i:i+60] for i in range(0, len(encrypted_shellcode), 60)]
    return '\n'.join(f'"{line}"' for line in formatted_lines)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scextractxor.py <file_name> <key>")
    else:
        file_path = sys.argv[1]
        key = sys.argv[2].encode()  # Convert key to bytes
        shellcode, error = read_file(file_path)
        if error:
            print(error)
        else:
            encrypted_shellcode = xor_encrypt(shellcode, key)
            formatted_shellcode = format_shellcode(encrypted_shellcode)
            print(f'unsigned char shellcode[] =\n{formatted_shellcode};')
