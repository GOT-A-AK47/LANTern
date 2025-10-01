# Contributing to LANTern 🔦

Thank you for your interest in contributing to LANTern! This document provides guidelines for contributing to the project.

## How Can I Contribute?

### Reporting Bugs 🐛

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** and description
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Screenshots** if applicable
- **System information**:
  - OS and version
  - Python version
  - LANTern version

### Suggesting Features 💡

Feature suggestions are welcome! Please:

- **Check existing issues** first
- **Explain the use case** and benefits
- **Describe the solution** you'd like
- Consider **alternatives** you've thought about

### Pull Requests 🔧

1. **Fork** the repository
2. **Create a branch** (`git checkout -b feature/AmazingFeature`)
3. **Make your changes**
4. **Test thoroughly**
5. **Commit** (`git commit -m 'Add AmazingFeature'`)
6. **Push** (`git push origin feature/AmazingFeature`)
7. **Open a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/LANTern.git
cd LANTern

# Install dependencies
pip install -r requirements.txt

# Run the application
python src/lantern.py
```

## Code Style

- Follow **PEP 8** guidelines
- Use **type hints** where appropriate
- Add **docstrings** to functions and classes
- Keep functions **focused and small**
- Write **descriptive variable names**

## Testing

Before submitting:

- Test on **multiple machines** if possible
- Verify **encryption** still works
- Check **P2P discovery** functionality
- Test both **group chat** and **private messages**
- Ensure **dark mode** works correctly

## Commit Messages

- Use the **imperative mood** ("Add feature" not "Added feature")
- Keep the first line **under 50 characters**
- Add detailed description if needed
- Reference issues with `#123`

Examples:
```
Add file sharing feature

Implements drag-and-drop file sharing with progress bars.
Files are encrypted before transfer.

Fixes #42
```

## Areas We Need Help With

- 📱 **Mobile apps** (Android/iOS)
- 📁 **File sharing** implementation
- 🎨 **UI/UX improvements**
- 🌍 **Translations** to other languages
- 📚 **Documentation** improvements
- 🧪 **Testing** and bug reports
- 🎙️ **Voice chat** features

## Questions?

Open an issue with the `question` label or start a discussion!

---

**Thank you for contributing to LANTern!** 🙏
