//go:build live

package ldapclient

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (f *revocationLiveFixture) clientRelays(image string) {
	// D4-test: Docker/Colima drops a multi-network container's published port
	// after disconnecting a bridge. A one-network non-root byte relay keeps the
	// client path stable while the separate peer bridge is physically removed.
	// No server replies are generated and no credentials are stored in relays.
	source := `package main
import("io";"net";"os")
func main(){
l,e:=net.Listen("tcp",":1389");if e!=nil{panic(e)}
for{c,e:=l.Accept();if e!=nil{return};go func(){defer c.Close();u,e:=net.Dial("tcp",os.Args[1]);if e!=nil{return};defer u.Close();go func(){io.Copy(c,u);c.Close()}();io.Copy(u,c)}()}
}`
	path := filepath.Join(f.temporary, "relay.go")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		f.t.Fatal(err)
	}
	arch := strings.TrimSpace(f.must("", "docker", "image", "inspect", "--format", "{{.Architecture}}", image))
	f.must("", "env", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "go", "build", "-o", filepath.Join(f.temporary, "relay"), path)
	dockerfile := fmt.Sprintf("FROM %s\nCOPY relay /tmp/relay\nUSER 999:999\nENTRYPOINT [\"/tmp/relay\"]\n", image)
	if err := os.WriteFile(filepath.Join(f.temporary, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
		f.t.Fatal(err)
	}
	tag := f.network + "-relay"
	f.must("", "docker", "build", "-q", "-t", tag, f.temporary)
	var names []string
	f.t.Cleanup(func() {
		for _, name := range names {
			_, _ = f.command("", "docker", "rm", "-f", name)
		}
		_, _ = f.command("", "docker", "image", "rm", tag)
	})
	for i, n := range f.names {
		name := n + "-relay"
		names = append(names, name)
		f.must("", "docker", "run", "-d", "--name", name, "--network", n+"-client", "-p", "127.0.0.1::1389", tag, n+":389")
		f.ports[i] = strings.TrimSpace(f.must("", "docker", "port", name, "1389/tcp"))
	}
}
