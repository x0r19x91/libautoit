package tidy

// Replacement for Tidy.exe
// Features:
//

import (
	"libautoit/lexer"
	"strings"
)

type IdentCase int

const (
	AllLower IdentCase = iota
	AllUpper
	AutoDetect
)

type indentInfo struct {
	identCase  IdentCase
	indent     int
	nSpaces    int
	useTabs    bool
	strLitSize int
	iIfState   int // state
	useExtraNl bool
	fnEndCmt   bool
	lexer      lexer.ITokenizer
	buf        string
	lines      *strings.Builder

	iStateExtraNl int
	iStateFuncCmt int
	currFunc      string
	currToken     *lexer.Token
	lastToken     *lexer.Token
}

func NewTidyInfo(lex lexer.ITokenizer) *indentInfo {
	return &indentInfo{
		identCase:  AutoDetect,
		indent:     0,
		nSpaces:    4,
		useTabs:    false,
		strLitSize: 80,
		iIfState:   0,
		lexer:      lex,
		useExtraNl: true,
		fnEndCmt:   true,
		lines:      new(strings.Builder),
		buf:        "",
	}
}

func (ii *indentInfo) SetUseExtraNewline(bEnable bool) {
	ii.useExtraNl = bEnable
}

func (ii *indentInfo) SetFuncComments(bEnable bool) {
	ii.fnEndCmt = bEnable
}

func (ii *indentInfo) SetIdentifierCase(iCase IdentCase) {
	ii.identCase = iCase
}

func (ii *indentInfo) SetIndentSpaces(nSpaces int) {
	ii.nSpaces = nSpaces
}

func (ii *indentInfo) SetUseTabs(useTabs bool) {
	ii.useTabs = useTabs
}

func (ii *indentInfo) SetMaxStringLiteralSize(mMax int) {
	ii.strLitSize = mMax
}

func (pp *indentInfo) Inc() {
	pp.indent++
}

func (pp *indentInfo) Dec() {
	pp.indent--
	if pp.indent < 0 {
		pp.indent = 0
	}
}

func (pp indentInfo) Current() int {
	return pp.indent
}

func (pp *indentInfo) pad() string {
	return addLeadingSpaces(pp.indent, pp.useTabs, pp.nSpaces)
}

func addLeadingSpaces(nIndent int, useTabs bool, nIndentWidth int) string {
	if useTabs {
		return strings.Repeat("\t", nIndent)
	} else {
		return strings.Repeat(" ", nIndent*nIndentWidth)
	}
}

// Clean up
func (pp *indentInfo) Tidy() string {
	identSet := make(map[string]string)
	for {
		pp.lastToken = pp.currToken
		pp.currToken = pp.lexer.NextToken()
		if pp.currToken.TokType == lexer.EOF {
			break
		}

		if pp.currToken.TokType == lexer.EOL {
			if pp.iIfState == 2 {
				pp.Dec()
			}
			pp.iIfState = 0
			pp.lines.WriteString(strings.TrimRight(pp.buf, " "))
			pp.lines.WriteRune('\n')
			if pp.iStateExtraNl == 1 {
				if pp.useExtraNl {
					pp.lines.WriteRune('\n')
				}
				pp.iStateExtraNl = 0
			}
			pp.buf = ""
			continue
		}
		if pp.currToken.NeedsExtraNewline() {
			if pp.iStateExtraNl == 0 {
				pp.iStateExtraNl = 1
			}
		}
		if pp.currToken.Value == "Then" {
			if pp.iIfState == 0 {
				// If condition Then stmt EOL
				pp.iIfState = 1
				// If Condition Then EOL
				//   ...
				// ElseIf ...
				//   ...
				// Else
				//   ...
				// EndIf
			}
		}
		if pp.currToken.Value == "Func" &&
			pp.currToken.TokType == lexer.Keyword {
			if pp.iStateFuncCmt == 0 {
				pp.iStateFuncCmt = 1 // seen "func"
			}
		}
		if pp.currToken.IsBlockEndKeyword() {
			pp.Dec()
			if pp.currToken.Value == "EndFunc" {
				if pp.fnEndCmt {
					pp.currToken.Value +=
						addLeadingSpaces(1, false, pp.nSpaces)
					pp.currToken.Value += "; -> "
					pp.currToken.Value += pp.currFunc
				}
				pp.iStateFuncCmt = 0
			}
		}
		if len(pp.buf) == 0 {
			pp.buf += pp.pad()
		}
		if pp.currToken.IsBlockStartKeyword() {
			pp.Inc()
		}
		if pp.currToken.TokType.IsOpenBracket() ||
			pp.currToken.TokType.IsCloseBracket() ||
			pp.currToken.TokType == lexer.OpStructRef || pp.currToken.TokType == lexer.Comma {
			old := pp.buf
			for len(pp.buf) > 0 && pp.buf[len(pp.buf)-1] == ' ' {
				pp.buf = pp.buf[:len(pp.buf)-1]
			}
			if len(pp.buf) > 0 {
				switch pp.buf[len(pp.buf)-1] {
				case '=':
					pp.buf += " "
				}
				lastCh := pp.buf[len(pp.buf)-1]
				if lexer.IsOperator(lastCh) || lastCh == '=' ||
					lastCh == ',' {
					pp.buf += " "
				}
			} else {
				pp.buf = old
			}
		}
		if (pp.currToken.TokType.IsOpenBracket() &&
			(pp.lastToken.TokType == lexer.Keyword ||
				pp.lastToken.TokType == lexer.OpAnd ||
				pp.lastToken.TokType == lexer.OpNot ||
				pp.lastToken.TokType == lexer.OpOr)) ||
			pp.currToken.TokType == lexer.OpTernaryQuestion ||
			pp.currToken.TokType == lexer.OpTernaryColon {
			pp.buf += " "
		}
		if pp.currToken.TokType == lexer.OpAssign || pp.currToken.TokType == lexer.OpEq {
			if strings.ContainsRune("[()]", rune(pp.buf[len(pp.buf)-1])) {
				pp.buf += " "
			}
		}
		if !strings.Contains(pp.buf, "Const") &&
			!strings.Contains(pp.buf, "Enum") {
			if pp.currToken.TokType == lexer.Identifier {
				// pp.currToken.Value = strings.ToLower(pp.currToken.Value)
			}
		} else {
			if pp.identCase == AutoDetect {
				// capitalize for constants
				if pp.currToken.TokType == lexer.Identifier {
					pp.currToken.Value = strings.ToUpper(pp.currToken.Value)
				}
			}
		}
		if pp.currToken.TokType == lexer.Identifier {
			kv := strings.ToLower(pp.currToken.Value)
			if _, ok := identSet[kv]; !ok {
				vv := pp.currToken.Value
				switch pp.identCase {
				case AllLower:
					vv = strings.ToLower(vv)
				case AllUpper:
					vv = strings.ToUpper(vv)
				}
				identSet[kv] = vv
			}
		}
		if pp.iIfState == 1 && pp.currToken.Value != "Then" {
			pp.iIfState = 2
		}
		if (pp.currToken.TokType.IsBinaryOp() || pp.currToken.TokType == lexer.Keyword) &&
			len(pp.buf) > 0 &&
			strings.ContainsRune("])", rune(pp.buf[len(pp.buf)-1])) {
			pp.buf += " "
		}

		if pp.currToken.TokType == lexer.Identifier {
			pp.currToken.Value = identSet[strings.ToLower(pp.currToken.Value)]
		}
		if pp.currToken.TokType == lexer.StrLit {
			// split into chunks of 80 bytes per line
			// "chunk[0]" & _
			// "chunk[1]" & _
			// "chunk[2]" & _
			// ...
			// "chunk[n-1]"
			vv := ""
			rwStr := pp.currToken.Value[1 : len(pp.currToken.Value)-1]
			var chunks []string
			i := 0
			for ; i < len(rwStr); i += pp.strLitSize {
				size := i + pp.strLitSize
				if size > len(rwStr) {
					size = len(rwStr)
				}
				chunks = append(chunks, rwStr[i:size])
			}
			for i = 0; i < len(chunks)-1; i++ {
				pp.Inc()
				vv += "\"" + chunks[i] + "\" & _\n" + pp.pad()
				pp.Dec()
			}
			if len(chunks) > 0 {
				vv += "\"" + chunks[len(chunks)-1] + "\""
			}
			if len(vv) == 0 {
				vv = "\"\""
			}
			pp.currToken.Value = vv
		}
		if pp.currToken.TokType == lexer.UserFunction ||
			pp.currToken.TokType == lexer.StdFunction {
			if pp.iStateFuncCmt == 1 && pp.fnEndCmt {
				pp.currFunc = pp.currToken.Value
				pp.iStateFuncCmt = 2
			}
		}
		pp.buf += pp.currToken.Value
		if !pp.currToken.TokType.IsOpenBracket() &&
			!pp.currToken.TokType.IsCloseBracket() &&
			pp.currToken.TokType != lexer.OpStructRef {
			pp.buf += " "
		}
	}
	return pp.lines.String()
}
