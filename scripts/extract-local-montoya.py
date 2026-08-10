import zipfile, os

# 1. Extract burp/api classes from burpsuite.jar
burp_jar_path = r"c:\path\to\burpsuite.jar"  # <-- Update this path
with zipfile.ZipFile(burp_jar_path, 'r') as z:
    for f in z.namelist():
        if f.startswith('burp/api/'):
            z.extract(f, '.')

# 2. Package into libs/montoya-api-real.jar
with zipfile.ZipFile('../libs/montoya-api-real.jar', 'w') as z:
    for root, dirs, files in os.walk('burp'):
        for f in files:
            path = os.path.join(root, f)
            z.write(path)
