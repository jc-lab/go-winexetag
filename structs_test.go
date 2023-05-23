package winexetag

import (
	"github.com/lunixbochs/struc"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_IMAGE_DOS_HEADER_Size(t *testing.T) {
	size, err := struc.Sizeof(&IMAGE_DOS_HEADER{})
	assert.NoError(t, err)
	assert.Equal(t, IMAGE_DOS_HEADER_SIZE, size)
}

func Test_IMAGE_FILE_HEADER_Size(t *testing.T) {
	size, err := struc.Sizeof(&IMAGE_FILE_HEADER{})
	assert.NoError(t, err)
	assert.Equal(t, IMAGE_FILE_HEADER_SIZE, size)
}

func Test_IMAGE_OPTIONAL_HEADER32_Size(t *testing.T) {
	size, err := struc.Sizeof(&IMAGE_OPTIONAL_HEADER32{})
	assert.NoError(t, err)
	assert.Equal(t, 96, size)
}

func Test_IMAGE_OPTIONAL_HEADER64_Size(t *testing.T) {
	size, err := struc.Sizeof(&IMAGE_OPTIONAL_HEADER64{})
	assert.NoError(t, err)
	assert.Equal(t, 112, size)
}

func Test_IMAGE_DATA_DIRECTORY_Size(t *testing.T) {
	size, err := struc.Sizeof(&IMAGE_DATA_DIRECTORY{})
	assert.NoError(t, err)
	assert.Equal(t, 8, size)
}
