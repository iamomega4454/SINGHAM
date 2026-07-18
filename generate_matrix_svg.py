import random

# Generate matrix.svg contents

width = 1000
height = 300

# Base characters and words
words = ["SINGHAM", "SECURITY", "THREAT", "MALWARE", "PHISHING", "SHIELD", "CYBER", "SCAN", "GUARD", "SAFE", "LOCK", "KEY", "HASH"]
chars = "0123456789ABCDEF!@#$%&*()_+-=[]{}|;:,.<>?"

def generate_string(length):
    # Mix words and characters
    res = []
    while len(res) < length:
        if random.random() < 0.3:
            word = random.choice(words)
            res.extend(list(word))
        else:
            res.append(random.choice(chars))
    return "".join(res[:length])

svg_cols = []

# Let's generate 42 columns to cover the width of 1000px
# Separation is about 24px
num_cols = 42
for i in range(num_cols):
    x = 10 + i * 24
    # Stagger positions slightly to make it less grid-like
    x += random.randint(-5, 5)
    
    # 3D Layers: Foreground, Midground, Background
    layer_type = random.choices(["front", "mid", "back"], weights=[40, 40, 20], k=1)[0]
    
    length = random.randint(12, 22)
    text_val = generate_string(length)
    
    # Customize parameters based on layer
    if layer_type == "front":
        font_size = random.randint(14, 16)
        duration = round(random.uniform(1.8, 2.6), 2)
        opacity = 1.0
        # Foreground fall distance
        start_y = -350
        end_y = 450
    elif layer_type == "mid":
        font_size = random.randint(11, 13)
        duration = round(random.uniform(2.6, 3.8), 2)
        opacity = 0.65
        start_y = -280
        end_y = 380
    else: # back
        font_size = random.randint(8, 10)
        duration = round(random.uniform(3.8, 5.5), 2)
        opacity = 0.35
        start_y = -220
        end_y = 320
        
    delay = round(random.uniform(-6.0, 0.0), 2)
    
    # Create keyframes for this specific column's animation to allow different start/end positions per layer
    # Or we can just use a single keyframe but since start/end y positions differ, we can define inline style / keyframe or translate
    # Wait, if we use translate, we can define separate class animations, or just a single animation using y coords and transform
    # A single keyframe using relative percentages or translate is cleaner if we just translate from -100% to 300px
    # Actually, we can use a CSS custom property for the translation or just separate animation names.
    # To keep it extremely simple and standard SVG/CSS, we can just define a few shared animation classes or styles:
    # Let's define keyframes for front, mid, back
    
    col_svg = f'  <text x="{x}" y="0" class="matrix-col col-{layer_type}" style="font-size: {font_size}px; opacity: {opacity}; animation-duration: {duration}s; animation-delay: {delay}s;">{text_val}</text>'
    svg_cols.append(col_svg)

svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="{height}" style="background:#0f172a; border-radius: 12px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5);">
  <defs>
    <linearGradient id="fade" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#00E6A8" stop-opacity="0" />
      <stop offset="25%" stop-color="#00E6A8" stop-opacity="0.1" />
      <stop offset="85%" stop-color="#00E6A8" stop-opacity="0.85" />
      <stop offset="100%" stop-color="#ffffff" stop-opacity="1" />
    </linearGradient>
  </defs>
  
  <style>
    @keyframes fall-front {{
      0% {{ transform: translateY(-350px); }}
      100% {{ transform: translateY(450px); }}
    }}
    @keyframes fall-mid {{
      0% {{ transform: translateY(-280px); }}
      100% {{ transform: translateY(380px); }}
    }}
    @keyframes fall-back {{
      0% {{ transform: translateY(-220px); }}
      100% {{ transform: translateY(320px); }}
    }}
    
    .matrix-col {{
      font-family: 'Consolas', 'Courier New', monospace;
      font-weight: 700;
      fill: url(#fade);
      writing-mode: vertical-rl;
      text-orientation: upright;
      animation-iteration-count: infinite;
      animation-timing-function: linear;
    }}
    
    .col-front {{
      animation-name: fall-front;
    }}
    
    .col-mid {{
      animation-name: fall-mid;
    }}
    
    .col-back {{
      animation-name: fall-back;
    }}
  </style>

{"\n".join(svg_cols)}
</svg>
"""

with open("/home/karthikkrishnan24/HACKATHON/SINGHAM/matrix.svg", "w") as f:
    f.write(svg_content)

print("SVG generated successfully!")
