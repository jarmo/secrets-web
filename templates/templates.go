package templates

import (
  "strings"
  "html/template"
  "io/ioutil"

  "github.com/jarmo/secrets-web/generated"
)

func Create() (*template.Template, error) {
  tmpl := template.New("")
  for name, file := range generated.Assets.Files {
    if file.IsDir() || !strings.HasSuffix(name, ".tmpl") {
      continue
    }
    content, err := ioutil.ReadAll(file)
    if err != nil {
      return nil, err
    }
    tmpl, err = tmpl.New(name).Parse(string(content))
    if err != nil {
      return nil, err
    }
  }
  return tmpl, nil
}

func Path(name string) string {
  return "/templates/views/" + name + ".tmpl"
}
