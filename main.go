package main

/*

Author: Alexey Orlov. ao-xaocms@xao.io
your SHOULD save information about me.

*/

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image"
	"image/draw"
	"io/ioutil"
	"net/http"
	"os"
	"runtime/debug"
	"strings"

	"sync"

	"github.com/Masterminds/sprig/v3"
	"github.com/chai2010/webp"
	"github.com/disintegration/imaging"

	"github.com/gin-gonic/gin"
	"github.com/yuin/goldmark"
	emoji "github.com/yuin/goldmark-emoji"
	goldmark_extension "github.com/yuin/goldmark/extension"
	goldmark_html "github.com/yuin/goldmark/renderer/html"
	"gopkg.in/yaml.v2"

	"github.com/microcosm-cc/bluemonday"
)

var dump_rest bool

var yaml_router yamlRouterStruct
var fetch_always []string

var template_func_map template.FuncMap

func readYaml(filename string, out interface{}) error {
	yamlFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	file_bytes, _ := ioutil.ReadAll(yamlFile)

	if err := yaml.Unmarshal(file_bytes, out); err != nil {
		return err
	}

	return nil
}

type FetchesRow struct {
	URL                  string   `yaml:"url"`
	Method               string   `yaml:"method"`
	Important            bool     `yaml:"important"`
	FetchAlways          bool     `yaml:"fetch_always"`
	Request              string   `yaml:"request"`
	Headers              []string `yaml:"headers"`
	RequestTemplate      *template.Template
	URLTemplate          *template.Template
	FetchHeadersTemplate *template.Template
}

/*
type MarkdownRow struct {
	Template       string   `yaml:"template"`
	TagsInTemplate []string `yaml:"tagsintemplate"`
	Markdown       goldmark.Markdown
}
*/

type yamlRouterStruct struct {
	Routers map[string]struct {
		Template string                 `yaml:"template"`
		Fetch    []string               `yaml:"fetch"`
		Env      map[string]interface{} //looks as .local in template
	} `yaml:"routers"`
	Fetches      map[string]FetchesRow        `yaml:"fetches"`
	FetchHeaders map[string]map[string]string `yaml:"fetch_headers"` //fetch_name: - arr
	//	Markdown     map[string]MarkdownRow       `yaml:"markdowns"`
	Env         map[interface{}]interface{} `yaml:"env"`
	StaticPaths map[string]string           `yaml:"static"`
}

/*        "url":"http://192.168.1.194:8055/items/buildings", */

func fetchTemplateForString(val string) *template.Template {
	t, err := template.New("").Funcs(sprig.FuncMap()).Parse(val)
	if err != nil {
		fmt.Printf("error in template='%s'\n", val)
		panic(err)
	}
	return t
}

//var markdown goldmark.Markdown
var bluemonday_policy *bluemonday.Policy

func func_sanitize(source string) template.HTML {
	return template.HTML(template.HTML(bluemonday_policy.Sanitize(source)))
}

func func_markdown( /* tplname string, */ source string) template.HTML {
	var buf bytes.Buffer
	//	fmt.Printf("XX=%v\n", tplname)
	//	fmt.Printf("AA=%v\n", yaml_router.Markdown[tplname])
	//	fmt.Printf("CC=%v\n", yaml_router.Markdown[tplname].Markdown)

	if err := markdown_glob.Convert([]byte(source), &buf); /* yaml_router.Markdown[tplname].Markdown.Convert([]byte(source), &buf)*/ err != nil {
		panic(err)
	}
	return template.HTML(buf.String())
}

func func_html2string(source template.HTML) string {
	return string(source)
}

func func_byte2string(in []byte) string {
	return string(in)
}

func func_str2js(in string) template.JS {
	return template.JS(in)
}
func func_str2html(in string) template.HTML {
	return template.HTML(in)
}
func func_str2attr(in string) template.HTMLAttr {
	return template.HTMLAttr(in)
}
func func_str2css(in string) template.CSS {
	return template.CSS(in)
}
func func_str2url(in string) template.URL {
	return template.URL(in)
}

var fetch_cache = make(map[string]interface{} /* map[string]interface{} */)
var fetch_cache_mutex = sync.RWMutex{}

func executeTemplateForFetch(
	tpl *template.Template,
	params map[string]string,
	env map[interface{}]interface{},
) (bytes.Buffer, error) {
	request_writer := bytes.Buffer{}

	env_for_execute_in_template := make(map[string]interface{})
	env_for_execute_in_template["params"] = params
	env_for_execute_in_template["env"] = env

	err := tpl.Execute(&request_writer, env_for_execute_in_template)
	if err != nil {
		fmt.Printf("err=%v\n", err)
		return request_writer, err
		//						panic(err)
	}
	return request_writer, nil

}

func fetchByName(c *gin.Context, fetch_name string) (interface{}, error) {
	fetch_obj, ok := yaml_router.Fetches[fetch_name]
	if !ok {
		return nil, errors.New("fetch not found : " + fetch_name)
	}

	var fetch_html_object interface{}
	//:= make(interface{})
	// make(map[string]interface{})

	var fetch_http_resp *http.Response
	var err error = nil

	params := make(map[string]string)

	for _, v := range c.Params {
		params[v.Key] = v.Value
	}

	executed_url_writer := bytes.Buffer{}

	if executed_url_writer, err = executeTemplateForFetch(fetch_obj.URLTemplate, params, yaml_router.Env); err != nil {
		return nil, err
	}

	get_url_str := executed_url_writer.String()

	http_client := &http.Client{}
	//headers
	executed_headers_writer := bytes.Buffer{}

	if fetch_obj.FetchHeadersTemplate != nil {
		if executed_headers_writer, err = executeTemplateForFetch(fetch_obj.FetchHeadersTemplate, params, yaml_router.Env); err != nil {
			return nil, err
		}
	}

	if fetch_obj.Method == "POST" || fetch_obj.Method == "GET" || fetch_obj.Method == "" {
		if dump_rest {
			fmt.Printf("FETCH (%s) url = %s\n", fetch_name, get_url_str)
		}

		fetch_method := fetch_obj.Method
		if fetch_method == "" {
			fetch_method = "GET"
		}

		//if v, ok := fetch_cache[get_url_str]; ok {
		//	return v, nil
		//} else {

		var body_io_reader *bytes.Buffer = nil

		if fetch_obj.Method == "POST" {
			executed_request_writer := bytes.Buffer{}
			if executed_request_writer, err = executeTemplateForFetch(fetch_obj.RequestTemplate, params, yaml_router.Env); err != nil {
				return nil, err
			}

			body_io_reader = bytes.NewBuffer(executed_request_writer.Bytes())
		}

		var http_req *http.Request

		if body_io_reader != nil {
			http_req, err = http.NewRequest(fetch_method, get_url_str, body_io_reader)
		} else {
			http_req, err = http.NewRequest(fetch_method, get_url_str, nil)
		}

		if err != nil {
			panic(err)
		}

		for _, header_line := range strings.Split(executed_headers_writer.String(), "\n") {
			if len(header_line) > 0 {
				header_line_splitted := strings.Split(header_line, ": ")
				header_key := header_line_splitted[0]
				if len(header_line) > 2 {
					header_value := header_line[len(header_key)+2:]
					http_req.Header.Set(header_key, header_value)
				}
			}
		}

		fetch_http_resp, err = http_client.Do(http_req)
	}

	if err != nil && fetch_obj.Important {
		return nil, errors.New("can't fetch important " + fetch_name)
	}

	if dump_rest {
		fmt.Printf("FETCH (%s) responsecode = %d header=%v\n", fetch_name, fetch_http_resp.StatusCode, fetch_http_resp.Header)
	}

	var json_err error
	if dump_rest {
		response_data, err_l := ioutil.ReadAll(fetch_http_resp.Body)
		if err_l != nil {
			return nil, fmt.Errorf("can't fetch (%s) read erro=%v ", fetch_name, err_l)
		}
		response_data_str := string(response_data)
		fmt.Printf("FETCH (%s) response_text = %s\n", fetch_name, response_data_str)

		json_err = json.NewDecoder(strings.NewReader(response_data_str)).Decode(&fetch_html_object)

	} else {

		json_err = json.NewDecoder(fetch_http_resp.Body).Decode(&fetch_html_object)
	}

	/*
		switch v := v.(type) {
		case []interface{}:
			// it's an array
		case map[string]interface{}:
			// it's an object
		default:
			// it's something else
		}
	*/

	if json_err != nil {
		return nil, fmt.Errorf("can't fetch (%s) json unmarshall error = %v ", fetch_name, json_err)
	}

	fetch_cache_mutex.Lock()
	fetch_cache[get_url_str] = fetch_html_object
	fetch_cache_mutex.Unlock()

	if dump_rest {
		fmt.Printf("FETCH (%s) response = %s\n", fetch_name, fetch_html_object)
	}

	return fetch_html_object, nil

}

func pageFunction(c *gin.Context, router_name string) error {

	fetches := make(map[string]interface{})
	fetchesMutex := sync.RWMutex{}
	var show500error error = nil

	router_row := yaml_router.Routers[c.FullPath()]

	should_fetch := make(map[string]string)
	for _, v := range fetch_always {
		should_fetch[v] = v
	}

	for _, fetch_name := range router_row.Fetch {
		should_fetch[fetch_name] = fetch_name
	}

	var wg sync.WaitGroup
	for _, fetch_name := range should_fetch {
		wg.Add(1)
		fetch_name_param := fetch_name
		go func() {
			func() {
				defer func() {
					if r := recover(); r != nil {
						panic_txt := fmt.Sprintln(r)
						show500error = fmt.Errorf("recovered: panic for fetch %s = %s", fetch_name_param, panic_txt)
						fmt.Println("stacktrace from panic: \n" + string(debug.Stack()))
					}
				}()

				fetch_result, err := fetchByName(c, fetch_name_param)
				if err != nil {
					show500error = err
				} else {
					fetchesMutex.Lock()
					fetches[fetch_name_param] = fetch_result
					fetchesMutex.Unlock()
				}
			}()
			wg.Done()
		}()
	}

	wg.Wait()

	if show500error != nil {
		c.AbortWithError(http.StatusInternalServerError, show500error)
		return show500error
	}

	params_str_map := make(map[string]string)

	for _, pv := range c.Params {
		params_str_map[pv.Key] = pv.Value
	}

	c.HTML(http.StatusOK, router_row.Template, gin.H{
		"fe":     fetches,
		"local":  router_row.Env,
		"env":    yaml_router.Env,
		"params": params_str_map,
	})
	return nil
}

func loadRouterYaml() {
	yaml_router = yamlRouterStruct{}
	fetch_always = []string{}

	if err := readYaml("conf/router.yml", &yaml_router); err != nil {
		panic(err)
	}

	for fetch_i := range yaml_router.Fetches {
		old_fetch := yaml_router.Fetches[fetch_i]
		old_fetch.RequestTemplate = fetchTemplateForString(old_fetch.Request)
		old_fetch.URLTemplate = fetchTemplateForString(old_fetch.URL)

		if old_fetch.Headers != nil {
			for _, fetch_head_name := range old_fetch.Headers {
				var header_txt bytes.Buffer
				for fetch_head_key, fetch_head_value := range yaml_router.FetchHeaders[fetch_head_name] {
					header_txt.WriteString(fetch_head_key)
					header_txt.WriteString(": ")
					header_txt.WriteString(fetch_head_value)
					header_txt.WriteString("\n")
				}
				old_fetch.FetchHeadersTemplate = fetchTemplateForString(header_txt.String())
			}
		} else {
			old_fetch.FetchHeadersTemplate = nil
		}

		yaml_router.Fetches[fetch_i] = old_fetch

		if old_fetch.FetchAlways {
			fetch_always = append(fetch_always, fetch_i)
		}
	}
}

/*
type customRenderer struct {
	Markdown_name string
	Template      *template.Template
}
*/
//func (c *customRenderer) renderImage(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
//}

//func newCustomRenderer() renderer.NodeRenderer {
//	return &customRenderer{}
//}

/*

func (c *customRenderer) RegisterFuncs(r renderer.NodeRendererFuncRegisterer) {
	//	fmt.Printf("REG v(%v)=%v\n", c.Markdown_name, yaml_router.Markdown)
	tags_in_template := yaml_router.Markdown[c.Markdown_name].TagsInTemplate
	for _, v := range tags_in_template {
		//		fmt.Printf("switch v=%v\n", v)
		switch v {
		case "link":
			r.Register(goldmark_ast.KindLink, c.renderLink)
		case "image":
			r.Register(goldmark_ast.KindImage, c.renderImage)
		case "heading":
			r.Register(goldmark_ast.KindHeading, c.renderHeading)
		case "table":
			r.Register(goldmark_ast_ext.KindTable, c.renderTable)
		case "tableHeader":
			r.Register(goldmark_ast_ext.KindTableHeader, c.renderTableHeader)
		case "tableRow":
			r.Register(goldmark_ast_ext.KindTableRow, c.renderTableRow)
		case "tableCell":
			r.Register(goldmark_ast_ext.KindTableCell, c.renderTableCell)
		}
	}
}
*/

/*
func (c *customRenderer) renderSomething(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool, templateName string) (goldmark_ast.WalkStatus, error) {
	//		n := node.(*goldmark_ast.Link)
	//	envs["title"] = string(reflect.Indirect(node).FieldByName("Title").Bytes())
	envs := make(map[string]interface{})
	envs["node"] = node
	envs["source"] = source
	envs["entering"] = entering
	envs["attrs"] = template.HTMLAttr(markdown_print_attrs(node))

	err := c.Template.ExecuteTemplate(w, templateName, envs)
	if err != nil {
		panic(err)
	}

	return goldmark_ast.WalkContinue, nil
}

func (c *customRenderer) renderLink(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool) (goldmark_ast.WalkStatus, error) {
	return c.renderSomething(w, source, node, entering, "link")
}
func (c *customRenderer) renderImage(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool) (goldmark_ast.WalkStatus, error) {
	return c.renderSomething(w, source, node, entering, "image")
}
func (c *customRenderer) renderHeading(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool) (goldmark_ast.WalkStatus, error) {
	return c.renderSomething(w, source, node, entering, "heading")
}
func (c *customRenderer) renderTable(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool) (goldmark_ast.WalkStatus, error) {
	return c.renderSomething(w, source, node, entering, "table")
}
func (c *customRenderer) renderTableHeader(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool) (goldmark_ast.WalkStatus, error) {
	return c.renderSomething(w, source, node, entering, "tableHeader")
}
func (c *customRenderer) renderTableRow(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool) (goldmark_ast.WalkStatus, error) {
	return c.renderSomething(w, source, node, entering, "tableRow")
}
func (c *customRenderer) renderTableCell(w util.BufWriter, source []byte, node goldmark_ast.Node, entering bool) (goldmark_ast.WalkStatus, error) {
	return c.renderSomething(w, source, node, entering, "tableCell")
}

func markdown_print_attrs(node goldmark_ast.Node) string {
	var w bytes.Buffer
	for _, attr := range node.Attributes() {
		_, _ = w.WriteString(" ")
		_, _ = w.Write(attr.Name)
		_, _ = w.WriteString(`="`)
		// TODO: convert numeric values to strings
		_, _ = w.Write(util.EscapeHTML(attr.Value.([]byte)))
		_ = w.WriteByte('"')
	}

	return w.String()
}
*/

var markdown_glob goldmark.Markdown

func initMarkdown() {

	markdown_glob = goldmark.New(
		goldmark.WithRendererOptions(
			goldmark_html.WithXHTML(),
			goldmark_html.WithUnsafe(),
		),
		goldmark.WithExtensions(
			goldmark_extension.Table,
			goldmark_extension.Strikethrough,
			goldmark_extension.Footnote,
			goldmark_extension.Typographer,
			goldmark_extension.DefinitionList,
			emoji.Emoji,

			goldmark_extension.NewLinkify(
				goldmark_extension.WithLinkifyAllowedProtocols([][]byte{
					[]byte("http:"),
					[]byte("https:"),
					[]byte("mailto:"),
					[]byte("ftp:"),
				}),
			),
		),
	)

	//	goldmark.WithParser()
	/*
		if _, ok := yaml_router.Markdown["default"]; !ok {
			yaml_router.Markdown["default"] =
				MarkdownRow{
					Template: "",
					//Markdown: goldmark.New(defaultGoldmarkOptions...),
				}
		}

		parser_options := goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
			parser.WithAttribute(),
		)

		parser_extensions := goldmark.WithExtensions(
			extension.Table,
			extension.Strikethrough,
			extension.Footnote,
			extension.Typographer,
			extension.Linkify,
			extension.DefinitionList,
			emoji.Emoji,
		)

		for md_name, md_v := range yaml_router.Markdown {
			md_old := md_v

			//		fmt.Printf("AZ=%v\n", md_v.TagsInTemplate)
			var renderer_opt goldmark.Option

			if md_v.Template == "" {
				renderer_opt = nil
			} else {
				tpl, err := template.New("").Funcs(template_func_map).ParseFiles("./templates/markdown/" + md_v.Template)
				if err != nil {
					panic(err)
				}

				parser_options = goldmark.WithParserOptions(
					parser.WithAutoHeadingID(),
					parser.WithAttribute(),

				)

				renderer_opt = goldmark.WithRendererOptions(
					renderer.WithNodeRenderers(
						util.Prioritized(
							&customRenderer{
								Markdown_name: md_name,
								Template:      tpl,
							},
							499),
						//					util.Prioritized(extension.NewTableHTMLRenderer(), 499),
					),
					//	goldmark_html.WithXHTML(),
					//goldmark_html.WithUnsafe(),
				)
			}

			//		extension.NewTableHTMLRenderer()

			defaultGoldmarkOptions := []goldmark.Option{
				parser_options,
				parser_extensions,
			}

			if renderer_opt != nil {
				defaultGoldmarkOptions = append([]goldmark.Option{renderer_opt}, defaultGoldmarkOptions...)
			}

			//		fmt.Printf("render opt for %v is v=%v\n", md_name, renderer_opt)
			md_old.Markdown = goldmark.New(defaultGoldmarkOptions...)

			yaml_router.Markdown[md_name] = md_old

		}

		//		markdown.Renderer().AddOptions(a)

	*/

}

func initRouter() {

	router := gin.Default()
	router.SetFuncMap(template_func_map)
	router.LoadHTMLGlob("templates/www/*")

	for router_name := range yaml_router.Routers {
		router.GET(router_name, func(c *gin.Context) {
			defer func() {
				if r := recover(); r != nil {
					panic_txt := fmt.Sprintln(r)

					fmt.Println("Recovered: panic = ", panic_txt)

					c.JSON(404, struct {
						Error string
					}{
						panic_txt,
					})

				}
			}()
			pageFunction(c, router_name)
		})
	}

	for static_key, static_value := range yaml_router.StaticPaths {
		router.Static(static_key, static_value)
	}

	router.Run(":8080")
	//	router.RunTLS(":8080", "./testdata/server.pem", "./testdata/server.key")
}

func initBluemonday() {
	bluemonday_policy = bluemonday.UGCPolicy() //.NewPolicy()
}

func func_lines(in string) []string {
	return strings.Split(in, "\n")
}

func initFuncMap() {

	fmap := make(map[string]any)

	local_func_map := template.FuncMap{
		"markdown":    func_markdown,
		"sanitize":    func_sanitize,
		"html2string": func_html2string,
		"b2s":         func_byte2string,
		"byte2string": func_byte2string,
		"implode":     strings.Join,
		"explode":     strings.Split,
		"lines":       func_lines,
		"str2js":      func_str2js,
		"str2css":     func_str2css,
		"str2html":    func_str2html,
		"str2attr":    func_str2attr,
		"str2url":     func_str2url,
		"image":       func_image,
		"image_fit":   func_image_fit,
	}

	for fk, fv := range sprig.FuncMap() {
		fmap[fk] = fv
	}

	for fk, fv := range local_func_map {
		fmap[fk] = fv
	}

	template_func_map = fmap

}

func if_env_true(env_name string) bool {
	fmt.Printf("getting env %s is ", env_name)
	env_r := os.Getenv(env_name)
	if env_r == "True" || env_r == "true" || env_r == "yes" || env_r == "YES" {
		fmt.Printf("true\n")
		return true
	} else {
		fmt.Printf("false\n")
		return false
	}

}

func initEnvAndParameters() {
	if if_env_true("DUMP_REST") || if_env_true("DUMP_FETCH") {
		dump_rest = true
	} else {
		dump_rest = false
	}
}

func initialize() {
	initEnvAndParameters()
	loadRouterYaml()
	initFuncMap()
	initBluemonday()
	initMarkdown()
	initRouter()

}

func main() {
	initialize()
}

type TemplateImage struct {
	img *image.NRGBA
}

func (ths *TemplateImage) Init(source string) error {
	src, err := imaging.Open(source)
	if err != nil {
		return fmt.Errorf("image init error: %s", err)
	}

	if img, ok := src.(*image.NRGBA); ok {
		ths.img = img
	} else {
		b := src.Bounds()
		m := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
		draw.Draw(m, m.Bounds(), src, b.Min, draw.Src)
		ths.img = m
	}
	return nil

}

func (ths *TemplateImage) Fit(width int, height int) *TemplateImage {
	ths.img = imaging.Fit(ths.img, width, height, imaging.Lanczos)
	return ths
}

func (ths *TemplateImage) Blur(bv float64) *TemplateImage {
	ths.img = imaging.Blur(ths.img, bv)
	return ths
}

func (ths *TemplateImage) Sharpen(bv float64) *TemplateImage {
	ths.img = imaging.Sharpen(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustGamma(bv float64) *TemplateImage {
	ths.img = imaging.AdjustGamma(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustContrast(bv float64) *TemplateImage {
	ths.img = imaging.AdjustContrast(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustBrightness(bv float64) *TemplateImage {
	ths.img = imaging.AdjustBrightness(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustSaturation(bv float64) *TemplateImage {
	ths.img = imaging.AdjustSaturation(ths.img, bv)
	return ths
}

func (ths *TemplateImage) Save(dest string, quality int) error {

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("image save error: %s", err)
	}
	defer f.Close()
	//Lossless: true,
	webp_opts := webp.Options{Quality: float32(quality)}

	if err := webp.Encode(f, ths.img, &webp_opts); err != nil {
		return fmt.Errorf("image save error: %s", err)
	}
	return nil

	/*
		err := imaging.Save(ths.img, dest, imaging.JPEGQuality(quality))
		if err != nil {
			return fmt.Errorf("image save error: %s", err)
		} else {
			return nil
		}
	*/
}

func func_image(source string) *TemplateImage {
	img := TemplateImage{}
	init_e := img.Init(source)
	if init_e != nil {
		return nil
	}
	return &img
}

func func_image_fit(source string, dest string, width int, height int, quality int) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	img := TemplateImage{}
	init_e := img.Init(source)
	if init_e != nil {
		return init_e
	}
	init_e = img.Fit(width, height).Save(dest, quality)
	return init_e
}
