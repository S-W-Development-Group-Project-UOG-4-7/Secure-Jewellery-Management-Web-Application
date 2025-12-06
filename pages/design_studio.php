<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SJM | AI Design Studio</title>
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">

    <style>
        /* LUXURY THEME STYLES */
        :root {
            --gold: #d4af37;
            --gold-glow: rgba(212, 175, 55, 0.5);
            --bg: #050505;
            --panel: #111;
            --text: #fff;
            --border: rgba(255, 255, 255, 0.1);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; overflow: hidden; }

        /* LAYOUT */
        .studio-container { display: grid; grid-template-columns: 350px 1fr; height: 100vh; }

        /* LEFT CONTROLS */
        .controls-panel {
            background: var(--panel); border-right: 1px solid var(--border);
            padding: 40px 30px; display: flex; flex-direction: column;
            z-index: 10; box-shadow: 10px 0 50px rgba(0,0,0,0.5);
        }

        .brand-back { color: var(--gold); text-decoration: none; font-size: 0.9rem; margin-bottom: 30px; display: flex; align-items: center; gap: 10px; }
        h1 { font-family: 'Playfair Display'; font-size: 2rem; margin-bottom: 10px; }
        p.subtitle { color: #888; font-size: 0.9rem; margin-bottom: 30px; line-height: 1.6; }

        .input-group { margin-bottom: 25px; }
        .input-label { display: block; color: var(--gold); font-size: 0.75rem; font-family: 'JetBrains Mono'; margin-bottom: 10px; letter-spacing: 1px; }
        
        .prompt-box {
            width: 100%; height: 120px; background: #080808; border: 1px solid #333;
            color: #fff; padding: 15px; border-radius: 8px; resize: none;
            font-family: 'Inter'; font-size: 0.95rem; outline: none; transition: 0.3s;
        }
        .prompt-box:focus { border-color: var(--gold); }

        /* Tags */
        .tags-container { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 10px; }
        .tag {
            padding: 6px 12px; background: #1a1a1a; border: 1px solid #333;
            border-radius: 20px; font-size: 0.8rem; cursor: pointer; transition: 0.3s; color: #ccc;
        }
        .tag:hover { border-color: var(--gold); color: var(--gold); }

        .btn-generate {
            margin-top: auto; width: 100%; padding: 18px;
            background: linear-gradient(135deg, var(--gold) 0%, #f9e5b9 100%);
            border: none; border-radius: 8px; color: #000; font-weight: 700;
            font-size: 1rem; cursor: pointer; transition: 0.3s;
            display: flex; justify-content: center; align-items: center; gap: 10px;
        }
        .btn-generate:hover { transform: translateY(-2px); box-shadow: 0 0 30px var(--gold-glow); }
        .btn-generate:disabled { opacity: 0.7; cursor: wait; }

        /* RIGHT VISUALIZER */
        .visualizer-panel {
            position: relative; background: radial-gradient(circle at center, #1a1a1a 0%, #000 100%);
            display: flex; justify-content: center; align-items: center;
        }

        .design-frame {
            width: 600px; height: 600px; position: relative;
            border: 1px solid var(--border); border-radius: 4px;
            display: flex; justify-content: center; align-items: center;
            background: #000; box-shadow: 0 20px 80px rgba(0,0,0,0.8);
            overflow: hidden; opacity: 0; transition: opacity 1s;
        }
        .design-frame.active { opacity: 1; }
        .design-image { width: 100%; height: 100%; object-fit: cover; transition: transform 0.5s; }
        .design-image:hover { transform: scale(1.05); }

        /* Loader */
        .ai-loader { position: absolute; text-align: center; display: none; }
        .ai-loader.active { display: block; }
        
        .loader-ring {
            width: 80px; height: 80px; border: 2px solid transparent;
            border-top: 2px solid var(--gold); border-radius: 50%;
            animation: spin 1s linear infinite; margin: 0 auto 20px;
        }
        .loader-text {
            font-family: 'JetBrains Mono'; color: var(--gold); font-size: 0.9rem;
            animation: pulse 1s infinite alternate;
        }

        /* Result Actions */
        .result-actions {
            position: absolute; bottom: 40px; display: flex; gap: 20px;
            opacity: 0; transform: translateY(20px); transition: 0.5s;
        }
        .result-actions.visible { opacity: 1; transform: translateY(0); }
        
        .action-btn {
            padding: 12px 25px; background: rgba(0,0,0,0.8); border: 1px solid var(--border);
            color: #fff; border-radius: 30px; cursor: pointer; backdrop-filter: blur(10px);
            display: flex; align-items: center; gap: 8px; transition: 0.3s;
        }
        .action-btn:hover { border-color: var(--gold); color: var(--gold); }

        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @keyframes pulse { 0% { opacity: 0.5; } 100% { opacity: 1; } }
    </style>
</head>
<body>

<div class="studio-container">
    <div class="controls-panel">
        <a href="index.php" class="brand-back"><i class="fa-solid fa-arrow-left"></i> Return to SJM</a>
        <h1>AI Design Studio</h1>
        <p class="subtitle">Describe your vision. Our neural engine will synthesize a unique jewellery concept in real-time.</p>

        <div class="input-group">
            <span class="input-label">PROMPT DESCRIPTION</span>
            <textarea id="promptInput" class="prompt-box" placeholder="e.g. A vintage Art Deco ring with a hexagonal sapphire center stone and diamond halo, set in platinum..."></textarea>
        </div>

        <div class="input-group">
            <span class="input-label">QUICK MODIFIERS</span>
            <div class="tags-container">
                <div class="tag" onclick="addTag('Rose Gold')">Rose Gold</div>
                <div class="tag" onclick="addTag('Platinum')">Platinum</div>
                <div class="tag" onclick="addTag('Emerald')">Emerald</div>
                <div class="tag" onclick="addTag('Vintage')">Vintage</div>
            </div>
        </div>

        <button id="generateBtn" class="btn-generate" onclick="generateDesign()">
            <i class="fa-solid fa-wand-magic-sparkles"></i> GENERATE CONCEPT
        </button>
    </div>

    <div class="visualizer-panel">
        <div id="aiLoader" class="ai-loader">
            <div class="loader-ring"></div>
            <div class="loader-text" id="loaderText">INITIALIZING ENGINE...</div>
        </div>

        <div id="designFrame" class="design-frame">
            <img id="resultImage" class="design-image" src="" alt="Generated Design">
        </div>

        <div id="resultActions" class="result-actions">
            <button class="action-btn" onclick="alert('Saved to Profile!')"><i class="fa-regular fa-heart"></i> Save</button>
            <button class="action-btn" onclick="alert('Quote Requested!')"><i class="fa-solid fa-tag"></i> Request Quote</button>
        </div>
    </div>
</div>

<script>
    function addTag(text) {
        const box = document.getElementById('promptInput');
        if (!box.value.includes(text)) box.value += (box.value.length > 0 ? ", " : "") + text;
    }

    async function generateDesign() {
        const prompt = document.getElementById('promptInput').value;
        if (!prompt) { alert("Please describe your design."); return; }

        const btn = document.getElementById('generateBtn');
        const loader = document.getElementById('aiLoader');
        const frame = document.getElementById('designFrame');
        const actions = document.getElementById('resultActions');
        const loaderText = document.getElementById('loaderText');

        // Reset UI
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> SYNTHESIZING...';
        frame.classList.remove('active');
        actions.classList.remove('visible');
        loader.classList.add('active');

        // Cinematic Loading Text
        const steps = ["ANALYZING PROMPT...", "SELECTING METALS...", "RENDERING LIGHTING..."];
        let i = 0;
        const interval = setInterval(() => { if(i < steps.length) loaderText.innerText = steps[i++]; }, 800);

        try {
            // Call PHP Backend
            const res = await fetch('api/ai_generate.php', {
                method: 'POST',
                body: JSON.stringify({ prompt: prompt }),
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await res.json();

            clearInterval(interval);
            loader.classList.remove('active');

            if (data.status === 'success') {
                document.getElementById('resultImage').src = data.image_url;
                frame.classList.add('active');
                setTimeout(() => actions.classList.add('visible'), 500);
            } else {
                alert("Error: " + data.message);
            }
        } catch (err) {
            clearInterval(interval);
            loader.classList.remove('active');
            alert("Connection Failed. Check your PHP server.");
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> GENERATE CONCEPT';
        }
    }
</script>
</body>
</html>