"""Exact retained Registry image, seven proposed mount targets, no Java."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from qualify_m2_discovery_frame_native import main
if __name__=='__main__':
    assert len(sys.argv)==3
    main(Path(sys.argv[1]),Path(sys.argv[2]))
