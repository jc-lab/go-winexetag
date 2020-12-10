package main

import (
	"errors"
	"io/ioutil"
	"net/http"
)

type byteArray = []byte
var FETCH_CACHE = make(map[string]byteArray)

func fetch(origin string, from string) ([]byte, error) {
	client := http.Client{}
	resp, _ := client.Get(ORIGIN + from)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("bad response code " + resp.Status)
	}
	res, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func fetchFrom(origin string, from string) ([]byte, error) {
	cached, incache := FETCH_CACHE[from]
	if incache {
		return cached, nil
	}

	res, err := fetch(origin, from)
	if err != nil {
		return nil, err
	}

	FETCH_CACHE[from] = res
	return res, nil
}

