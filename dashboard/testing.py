from pathlib import Path

# A fixed Vite manifest, so pages render without a production build.
TEST_MANIFEST = Path(__file__).resolve().parent / "testdata" / "manifest.json"
