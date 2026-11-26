package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func hasLocalImageReference(images []types.ImageSummary, ref string) bool {
	digestSuffix := ""
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		digestSuffix = ref[i:]
	}

	for _, image := range images {
		for _, tag := range image.RepoTags {
			if tag == ref {
				return true
			}
		}
		for _, digest := range image.RepoDigests {
			if digestSuffix != "" && strings.HasSuffix(digest, digestSuffix) {
				return true
			}
		}
	}
	return false
}

func TestHasLocalImageReference(t *testing.T) {
	const pinned = "mritd/shadowsocks@sha256:7b6d3b887eb2bf5de27bc164580653baff9f6b9e8a460baaf23e100ca0353405"
	if !hasLocalImageReference([]types.ImageSummary{{RepoDigests: []string{"docker.io/" + pinned}}}, pinned) {
		t.Fatal("did not find the pinned image in RepoDigests")
	}
	if hasLocalImageReference([]types.ImageSummary{{RepoDigests: []string{"docker.io/mritd/shadowsocks@sha256:0000000000000000000000000000000000000000000000000000000000000000"}}}, pinned) {
		t.Fatal("matched a different image digest")
	}
	if !hasLocalImageReference([]types.ImageSummary{{RepoTags: []string{"mritd/shadowsocks:latest"}}}, "mritd/shadowsocks:latest") {
		t.Fatal("did not find a tagged image in RepoTags")
	}
}

func startContainer(cfg *container.Config, hostCfg *container.HostConfig, name string) (string, error) {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}
	defer c.Close()

	if !isDarwin {
		hostCfg.NetworkMode = "host"
	}

	container, err := c.ContainerCreate(context.Background(), cfg, hostCfg, nil, nil, name)
	if err != nil {
		return "", err
	}

	if err = c.ContainerStart(context.Background(), container.ID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}

	response, err := c.ContainerAttach(context.Background(), container.ID, types.ContainerAttachOptions{
		Stdout: true,
		Stderr: true,
		Logs:   true,
		Stream: true,
	})
	if err != nil {
		return "", err
	}

	go func() {
		response.Reader.WriteTo(os.Stderr)
	}()

	return container.ID, nil
}

func cleanContainer(id string) error {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer c.Close()

	removeOpts := types.ContainerRemoveOptions{Force: true}
	return c.ContainerRemove(context.Background(), id, removeOpts)
}
