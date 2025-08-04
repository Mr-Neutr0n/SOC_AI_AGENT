#!/usr/bin/env python3
"""
SOC AI Agent Setup Script

This script helps initialize and configure the SOC AI Agent project.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def check_prerequisites():
    """Check if required tools are installed"""
    print("🔍 Checking prerequisites...")
    
    requirements = {
        'python': 'python3 --version',
        'gcloud': 'gcloud --version',
        'pip': 'pip --version'
    }
    
    missing = []
    
    for tool, command in requirements.items():
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ {tool}: Found")
            else:
                missing.append(tool)
                print(f"❌ {tool}: Not found")
        except FileNotFoundError:
            missing.append(tool)
            print(f"❌ {tool}: Not found")
    
    if missing:
        print(f"\n❌ Missing prerequisites: {', '.join(missing)}")
        print("\nPlease install the missing tools and run this script again.")
        return False
    
    print("✅ All prerequisites found!")
    return True

def setup_environment():
    """Set up Python environment and install dependencies"""
    print("\n📦 Setting up Python environment...")
    
    # Create virtual environment if it doesn't exist
    venv_path = Path('venv')
    if not venv_path.exists():
        print("Creating virtual environment...")
        subprocess.run([sys.executable, '-m', 'venv', 'venv'])
    
    # Determine the correct python and pip paths
    if sys.platform == 'win32':
        python_path = venv_path / 'Scripts' / 'python.exe'
        pip_path = venv_path / 'Scripts' / 'pip.exe'
    else:
        python_path = venv_path / 'bin' / 'python'
        pip_path = venv_path / 'bin' / 'pip'
    
    # Upgrade pip
    print("Upgrading pip...")
    subprocess.run([str(pip_path), 'install', '--upgrade', 'pip'])
    
    # Install requirements
    print("Installing dependencies...")
    subprocess.run([str(pip_path), 'install', '-r', 'requirements.txt'])
    
    print("✅ Python environment setup complete!")
    print(f"📝 To activate: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)")

def create_env_file():
    """Create .env file from template"""
    print("\n🔧 Setting up environment configuration...")
    
    env_file = Path('.env')
    env_example = Path('env.example')
    
    if env_file.exists():
        print("⚠️  .env file already exists, skipping creation")
        return
    
    if env_example.exists():
        shutil.copy(env_example, env_file)
        print("✅ Created .env file from template")
        print("📝 Please edit .env file with your actual configuration values")
    else:
        print("❌ env.example file not found")

def validate_gcp_setup():
    """Validate Google Cloud setup"""
    print("\n☁️  Validating Google Cloud setup...")
    
    # Check if authenticated
    try:
        result = subprocess.run(['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            print(f"✅ Authenticated as: {result.stdout.strip()}")
        else:
            print("❌ Not authenticated with gcloud")
            print("📝 Run: gcloud auth login")
            return False
    except Exception as e:
        print(f"❌ Error checking authentication: {e}")
        return False
    
    # Check if project is set
    try:
        result = subprocess.run(['gcloud', 'config', 'get-value', 'project'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            print(f"✅ Default project: {result.stdout.strip()}")
        else:
            print("⚠️  No default project set")
            print("📝 Run: gcloud config set project YOUR_PROJECT_ID")
    except Exception as e:
        print(f"❌ Error checking project: {e}")
    
    return True

def setup_git_hooks():
    """Set up git hooks for development"""
    print("\n🔗 Setting up git hooks...")
    
    git_dir = Path('.git')
    if not git_dir.exists():
        print("⚠️  Not a git repository, skipping git hooks setup")
        return
    
    hooks_dir = git_dir / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    
    # Create pre-commit hook
    pre_commit_hook = hooks_dir / 'pre-commit'
    if not pre_commit_hook.exists():
        hook_content = """#!/bin/bash
# SOC AI Agent Pre-commit Hook

echo "Running pre-commit checks..."

# Run basic Python syntax check
python -m py_compile soc_agent/agent.py main.py test_agent.py

if [ $? -ne 0 ]; then
    echo "❌ Python syntax check failed"
    exit 1
fi

echo "✅ Pre-commit checks passed"
exit 0
"""
        pre_commit_hook.write_text(hook_content)
        pre_commit_hook.chmod(0o755)
        print("✅ Created pre-commit hook")
    else:
        print("⚠️  Pre-commit hook already exists")

def print_next_steps():
    """Print next steps for the user"""
    print("\n🎉 Setup complete! Next steps:")
    print("\n1. 📝 Configure your environment:")
    print("   - Edit .env file with your API keys and project settings")
    print("   - Update config.yaml if needed")
    
    print("\n2. 🚀 Deploy the agent:")
    print("   - Run: ./deploy.sh")
    print("   - Or follow manual deployment steps in IMPLEMENTATION.md")
    
    print("\n3. 🧪 Test the agent:")
    print("   - Run: python test_agent.py --project-id YOUR_PROJECT_ID --local-only")
    print("   - Or test with cloud services after deployment")
    
    print("\n4. 📚 Read the documentation:")
    print("   - README.md: Original specifications")
    print("   - IMPLEMENTATION.md: Complete implementation guide")
    
    print("\n5. 🔧 Optional configurations:")
    print("   - Set up Slack webhook for notifications")
    print("   - Get VirusTotal and AbuseIPDB API keys")
    print("   - Configure Chronicle Security Operations if available")
    
    print("\n📖 For help and troubleshooting, see IMPLEMENTATION.md")

def main():
    """Main setup function"""
    print("🚀 SOC AI Agent Setup")
    print("=" * 50)
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Setup Python environment
    setup_environment()
    
    # Create environment file
    create_env_file()
    
    # Validate GCP setup
    validate_gcp_setup()
    
    # Setup git hooks
    setup_git_hooks()
    
    # Print next steps
    print_next_steps()
    
    print("\n✅ Setup completed successfully!")

if __name__ == "__main__":
    main() 