# Phishing Detector Extension - Installation Guide

## Quick Fix for Icon Error

If you encountered the "Could not load icon" error, follow these steps:

### Step 1: Verify All Icons Exist
Make sure all required icon files are present:
- `icons/icon16.png` ✅
- `icons/icon32.png` ✅  
- `icons/icon48.png` ✅
- `icons/icon128.png` ✅

### Step 2: Check File Permissions
Ensure icon files have proper permissions:
```bash
# On Windows: Right-click → Properties → uncheck "Read-only"
# On Mac/Linux: chmod 644 icons/*.png
```

### Step 3: Reinstall Extension
1. Remove the existing extension from Chrome
2. Restart Chrome browser
3. Follow the installation steps below

## Complete Installation Steps

### Option 1: Chrome Web Store (Recommended - Coming Soon)
1. Visit Chrome Web Store
2. Search "Advanced Phishing Detector"
3. Click "Add to Chrome"

### Option 2: Developer Mode Installation

#### Prerequisites
- Chrome Browser (version 88+)
- Python 3.8+ (for backend)
- Internet connection

#### Step 1: Setup Python Backend
1. Open terminal/command prompt
2. Navigate to extension folder:
   ```bash
   cd path/to/phishing-detector-extension
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the Flask server:
   ```bash
   python phishing_detector.py
   ```
5. Keep this terminal window open (server must run continuously)

#### Step 2: Install Browser Extension
1. Open Chrome browser
2. Go to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select the `phishing-detector-extension` folder
6. Extension icon should appear in toolbar

#### Step 3: Verify Installation
1. Check extension icon appears in Chrome toolbar
2. Click icon to open popup - should show "Active" status
3. Visit a test website to verify protection works

### Option 3: Manual File Installation

If automatic installation fails:

1. **Create Extension Folder Structure:**
   ```
   phishing-detector-extension/
   ├── manifest.json
   ├── background.js
   ├── content.js
   ├── popup.html
   ├── popup.js
   ├── popup.css
   ├── warning.html
   ├── phishing_detector.py
   ├── requirements.txt
   └── icons/
       ├── icon16.png
       ├── icon32.png
       ├── icon48.png
       └── icon128.png
   ```

2. **Copy Files:**
   - Download all files to the extension folder
   - Ensure icon files are in `icons/` subdirectory
   - Verify all file names match exactly

3. **Install in Chrome:**
   - Follow Developer Mode steps above

## Troubleshooting

### Common Issues

#### 1. "Could not load manifest"
- **Solution**: Check `manifest.json` syntax and encoding
- Verify all required fields are present
- Ensure file is valid JSON

#### 2. "Could not load icon"
- **Solution**: 
  - Verify all 4 icon files exist in `icons/` folder
  - Check file extensions (.png not .PNG)
  - Ensure icons are valid PNG files

#### 3. "Extension not working"
- **Solution**:
  - Check if Python backend is running
  - Verify no firewall blocking port 5000
  - Check Chrome console for errors (F12 → Console)

#### 4. "Popup shows 'Loading...'"
- **Solution**:
  - Ensure Flask server is running
  - Check network connection
  - Verify API endpoint is accessible

### Debug Mode

Enable debug logging:
1. Right-click extension icon → "Inspect popup"
2. Open Console tab
3. Check for error messages
4. Report issues with console logs

### System Requirements

- **Operating System**: Windows 10+, macOS 10.12+, Linux (Ubuntu 18.04+)
- **Browser**: Chrome 88+, Firefox 85+, Edge 88+
- **Python**: 3.8 or higher
- **RAM**: Minimum 4GB
- **Storage**: 50MB free space
- **Network**: Internet connection required

### Firewall Configuration

If using firewall, allow:
- Port 5000 (Flask server)
- Chrome browser
- Python executable

### Antivirus Considerations

Some antivirus software may block:
- Python scripts
- Local web servers
- Browser extensions

Add exceptions for:
- `phishing_detector.py`
- Chrome browser
- Extension folder

## Getting Help

### Support Channels
- **GitHub Issues**: Report bugs and feature requests
- **Email**: security@example.com
- **Documentation**: Check README.md for detailed information

### Community
- **Discord**: Join our community server
- **Reddit**: r/PhishingDetector
- **Twitter**: @PhishingDetector

## Verification

After installation, verify:
1. ✅ Extension icon appears in toolbar
2. ✅ Popup opens and shows status
3. ✅ Python server is running without errors
4. ✅ Test websites are properly analyzed

## Next Steps

1. **Configure Settings**: Click extension icon → Settings
2. **Test Protection**: Visit test phishing sites
3. **Report Issues**: Use built-in reporting system
4. **Stay Updated**: Check for updates regularly

---

**Still having issues?** 
- Check the troubleshooting section above
- Verify all installation steps were followed
- Contact support with error details

**Happy Safe Browsing!** 🛡️