import os
import sys

def force_reset():
    target = "bot.py"
    if len(sys.argv) > 1:
        target = sys.argv[1]

    if not os.path.exists(target):
        print(f"❌ '{target}' not found!")
        input("Press Enter to exit...")
        return

    print(f"🔍 Reading {target}...")
    try:
        with open(target, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        print("⚠️  UTF-8 decode failed, trying latin-1...")
        with open(target, 'r', encoding='latin-1') as f:
            lines = f.readlines()

    # Find the REAL start of the bot
    start_index = -1
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("import discord") or s.startswith("from discord"):
            start_index = i
            print(f"✅ Found bot start at line {i+1}: {s}")
            break
    
    if start_index == -1:
        print("❌ Could not find 'import discord' or 'from discord'.")
        print("   Is this a discord bot file?")
        input("Press Enter to exit...")
        return

    # Check if there is garbage before it
    if start_index == 0:
        print("✅ File looks clean (starts with import).")
        print("   You can proceed to run integrate.bat")
    else:
        print(f"⚠️  Found {start_index} lines of header/garbage before import.")
        print("   TRUNCATING FILE...")
        
        new_content = "".join(lines[start_index:])
        
        # Add a clean Shebang just in case
        # new_content = "# clean start\n" + new_content
        
        backup = target + ".CORRUPT_BACKUP"
        try:
            with open(backup, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"   (Backup saved to {backup})")
        except: pass

        with open(target, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print("✅ SUCCESS: bot.py has been reset to its original state.")
        print("🚀 NOW you can run 'integrate.bat' safely.")

    input("\nPress Enter to exit...")

if __name__ == "__main__":
    force_reset()
