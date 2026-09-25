import os
import tempfile

# TestClient sends "Host: testserver"; the console only answers to hosts it recognises
os.environ.setdefault("KODAND_ALLOWED_HOSTS", "testserver")
# never read or write the developer's real ~/.kodand from tests
os.environ.setdefault("KODAND_HOME", tempfile.mkdtemp(prefix="kodand-test-home-"))
