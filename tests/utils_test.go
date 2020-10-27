package tests

import (
    "bytes"
    "io/ioutil"
    "libautoit"
    "libautoit/tidy"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestGetScripts(t *testing.T) {
    file := `C:\Users\x0r19x91\Desktop\libautoit\tests\Build.exe`
    data, err := ioutil.ReadFile(file)
    if err != nil {
        t.Error(err)
    }
    res, err := libautoit.GetScripts(data)
    if err != nil || len(res.Resources) == 0 {
        t.Error(err)
        return
    }
    os.Mkdir("dump", 0666)
    for _, r := range res.Resources {
        t.Log(r)
        if !r.Decompress() {
            t.Errorf("Decompessor Failed.")
        }
        if r.IsAutoItScript(500) {
            r.Data = bytes.ReplaceAll(r.Data, []byte{13, 10}, []byte{10})
            lex := r.CreateTokenizer()
            tidyInfo := tidy.NewTidyInfo(lex)
            tidyInfo.SetFuncComments(true)
            tidyInfo.SetIdentifierCase(tidy.AutoDetect)
            tidyInfo.SetIndentSpaces(4)
            tidyInfo.SetMaxStringLiteralSize(160)
            tidyInfo.SetUseExtraNewline(true)
            tidyInfo.SetUseTabs(false)
            cleaned := tidyInfo.Tidy()
            r.Data = []byte(cleaned)
            t.Log("Cleaned")
        }
        ioutil.WriteFile("dump/"+clean(r.Path), r.Data, 0666)
        t.Logf("Writing %d bytes to %s\n", len(r.Data), filepath.Base(r.Path))
    }
}

func clean(name string) string {
    name = strings.ReplaceAll(name, "<", "")
    name = strings.ReplaceAll(name, ">", "")
    name = filepath.Base(name)
    if !strings.ContainsRune(name, '.') {
        name += ".bin"
    }
    return name
}
