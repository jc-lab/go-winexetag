package winexetag

import (
	"github.com/kardianos/osext"
	"io/ioutil"
)

func GetSelfInstallationTag() (result string, err error) {
	exe, err := osext.Executable()
	if err != nil {
		return
	}

	exeContents, err := ioutil.ReadFile(exe)
	if err != nil {
		return
	}

	bin, err := NewBinary(exeContents)
	if err != nil {
		return
	}

	tag, err := bin.GetTag()
	if err != nil {
		return
	}

	return string(tag), nil
}

