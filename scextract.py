import sys
import re

def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            pattern = r"\b(?:mov|movsxd|ret|cmp|lea|call|inc|jmp|movzx|push|nop|ret|xor|sub|pop|jb|add|je|test)\b.*"
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
            return "unsigned char shellcode[] =" + "\n" + content + ";"
    except FileNotFoundError:
        return f"file '{file_path}' not found ."
    except Exception as e:
        return f"Cannot read file cuz : {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: pythons scextract.py <file_name>")
    else:
        file_path = sys.argv[1]
        file_content = read_file(file_path)
        print(file_content)
