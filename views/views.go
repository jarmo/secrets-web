package views

import (
	"strings"
	"html/template"
	"io/ioutil"

	"github.com/jarmo/secrets-web/generated"
)

func Initialize() (*template.Template, error) {
	view := template.New("")
	for name, file := range generated.Assets.Files {
		if file.IsDir() || !strings.HasSuffix(name, ".tmpl") {
			continue
		}
		content, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, err
		}
		view, err = view.New(name).Parse(string(content))
		if err != nil {
			return nil, err
		}
	}
	return view, nil
}
