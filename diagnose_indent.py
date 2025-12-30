try:
    with open('bot.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    start = max(0, 1180)
    end = min(len(lines), 1200)
    
    print(f"--- CONTENT OF bot.py AROUND LINE 1190 ---")
    for i in range(start, end):
        print(f"{i+1}: {lines[i].rstrip()}")
        
except Exception as e:
    print(f"Error reading file: {e}")
    
input("Press Enter...")
