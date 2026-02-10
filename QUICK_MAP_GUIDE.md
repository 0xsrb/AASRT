# 🗺️ Quick Map Guide

## How to See the Enhanced Map

### Step 1: Start the Dashboard
```bash
streamlit run app.py
```

### Step 2: Run a Scan
1. Open browser to `http://localhost:8501`
2. In sidebar, select a template (e.g., "clawdbot_instances")
3. Check "I accept mission parameters"
4. Click "🚀 INITIATE SCAN"

### Step 3: View the Map
Scroll down to the **"🌍 GALACTIC THREAT MAP"** section

## 🎮 New Controls

### Map Style Selector
```
🗺️ MAP STYLE: [3D Globe ▼]
```
- **3D Globe** - Rotating sphere (most impressive!)
- **Flat Map** - Traditional 2D view
- **Dark Matter** - Dark equirectangular
- **Natural Earth** - Natural projection

### Interactive Options
```
☐ ⚡ Show Threat Connections
☑ 💫 Animated Markers
```

### Map Controls (Bottom Center)
```
[🔄 AUTO ROTATE]  [⏸️ PAUSE]
```

## 🎨 What You'll See

### Main Map (Left Side)
- **Large colored markers** showing threats
- **Different shapes** for different severities:
  - 💎 Red Diamonds = CRITICAL
  - ⬛ Orange Squares = HIGH  
  - ⚪ Yellow Circles = MEDIUM
  - ⚪ Green Circles = LOW
- **Hover over markers** for detailed info
- **Click and drag** to rotate globe
- **Scroll** to zoom in/out

### Stats Panel (Top)
```
🛰️ LOCATED    🌐 SYSTEMS    🏙️ SECTORS    ⭐ HOTSPOT
    32            12            24         Germany
```

### Country Rankings (Right Side)
```
🏴 TOP SYSTEMS
Germany         ████████████ 12
United States   ████████ 8
France          ██████ 6
...
```

### Threat Density Chart (Right Side)
Horizontal bar chart showing average risk per country

### New Analysis Section (Bottom)
```
📡 THREAT SURFACE ANALYSIS

🎯 PORT DISTRIBUTION        🔧 SERVICE BREAKDOWN
[Bar Chart]                 [Donut Chart]
```

## 💡 Pro Tips

1. **Best View**: Start with "3D Globe" + "Animated Markers"
2. **For Presentations**: Enable "Show Threat Connections" for critical threats
3. **For Analysis**: Switch to "Flat Map" to see all threats at once
4. **Performance**: Disable animations if map is slow
5. **Screenshots**: Use "⏸️ PAUSE" before taking screenshots

## 🎯 Understanding the Markers

### Size
- Larger markers = Higher risk score
- Size range: 15px - 50px
- Formula: `size = max(15, risk_score * 5)`

### Color
- 🔴 Red (#FF2D2D) = Critical (9.0-10.0)
- 🟠 Orange (#FF6B35) = High (7.0-8.9)
- 🟡 Yellow (#FFE81F) = Medium (4.0-6.9)
- 🟢 Green (#39FF14) = Low (0.0-3.9)

### Hover Info
```
192.168.1.1:8080
⚡ Risk: 10.0/10
📍 Berlin, Germany
🔧 nginx
```

## 🚀 Quick Actions

### Rotate Globe Manually
- Click and drag on the globe
- Works in "3D Globe" mode only

### Zoom In/Out
- Scroll wheel up = Zoom in
- Scroll wheel down = Zoom out

### Focus on Region
- Double-click on a country
- Map will zoom to that region

### Toggle Threat Category
- Click legend item (e.g., "CRITICAL")
- Hides/shows that category

### Reset View
- Refresh the page
- Or change map style and back

## 📊 Reading the Charts

### Port Distribution
- Shows which ports are most exposed
- Higher bars = More targets on that port
- Common ports: 80, 443, 8080, 3000

### Service Breakdown
- Shows technology distribution
- Larger slices = More common services
- Common services: nginx, apache, node

### Threat Density
- Shows average risk by country
- Longer bars = Higher average risk
- Color gradient indicates severity

## 🎬 Demo Scenario

1. **Launch**: `streamlit run app.py`
2. **Scan**: Select "clawdbot_instances" template
3. **Wait**: ~5 seconds for scan to complete
4. **Scroll**: Down to map section
5. **Interact**: 
   - Try rotating the globe
   - Hover over markers
   - Click "AUTO ROTATE"
   - Toggle "Show Threat Connections"
   - Change to "Flat Map"
6. **Analyze**:
   - Check top countries
   - Review port distribution
   - Examine service breakdown

## 🎨 Visual Features

### Animations
- ✨ Smooth marker transitions
- 🌍 Globe auto-rotation (3°/frame)
- 💫 Hover glow effects
- 🌊 Pulsing connections

### Styling
- 🌌 Transparent background (space theme)
- 🌊 Cyan coastlines and borders
- 🌑 Dark land and ocean
- ⭐ Glowing markers
- 🎯 Professional tooltips

## 🔧 Customization

Want to change colors or sizes? Edit `app.py` around line 1100:

```python
# Marker colors
('critical', '#FF2D2D', 'CRITICAL', 'diamond')

# Marker size
df_map['size'] = df_map['risk_score'].apply(lambda x: max(15, x * 5))

# Map height
height=650
```

## 📱 Mobile/Tablet

The map works on mobile devices:
- Touch to rotate
- Pinch to zoom
- Tap markers for info
- Responsive layout

## 🎉 Enjoy!

The enhanced map makes threat visualization impressive and informative. Perfect for:
- 🎤 Security presentations
- 📊 Executive dashboards
- 🔍 Threat hunting
- 📈 Trend analysis
- 🎓 Security training

**May the Force be with your reconnaissance!** ⭐
