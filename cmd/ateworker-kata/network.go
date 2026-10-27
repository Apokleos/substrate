//go:build linux

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim"
	actornet "go.ate.dev/substrate/internal/ateworker/actornet"
	"go.ate.dev/substrate/internal/netns"
	"go.ate.dev/substrate/internal/nodepath"
	"golang.org/x/sys/unix"
)

const (
	kataTapName  = "tap0_kata"
	kataGuestMAC = "02:a8:1e:00:00:02"
	gatewayMAC   = "02:a8:1e:00:00:01"
	kataTapMTU   = 1500
)

var gatewayHWAddr = actornet.MustParseMAC(gatewayMAC)

func setupKataNetwork(ctx context.Context, session *actornet.SandboxSession, sandboxID string) (string, error) {
	if session == nil || session.Network == nil {
		return "", errors.New("sandbox network session is required")
	}
	ns := session.Network.RuntimeNetNS
	if err := setupKataTap(ctx, ns, kataTapName); err != nil {
		return "", err
	}
	netnsPath := nodepath.ActorNetNSPath(session.Network.ActorUID)
	_, err := katashim.WriteHostTapDANConfig(katashim.DefaultDANConfigDir, sandboxID, katashim.HostTapDANConfig{
		NetNSPath:   netnsPath,
		TapName:     kataTapName,
		GuestMAC:    kataGuestMAC,
		IPAddresses: []string{actornet.ActorVethIP + "/30"},
		MTU:         kataTapMTU,
		Routes: []katashim.DANRoute{
			{Destination: actornet.ActorVethSubnet, Scope: uint32(unix.RT_SCOPE_LINK)},
			{Gateway: actornet.ActorVethGateway},
		},
	})
	if err != nil {
		_ = removeKataTap(ctx, ns, kataTapName)
		return "", err
	}
	return netnsPath, nil
}

func setupKataTap(ctx context.Context, ns netns.Handle, name string) error {
	return netns.Do(ctx, ns, func(context.Context) error {
		if old, err := netlink.LinkByName(name); err == nil {
			if err := netlink.LinkDel(old); err != nil {
				return err
			}
		}
		tap := &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: name, MTU: kataTapMTU},
			Mode:      netlink.TUNTAP_MODE_TAP,
			Flags:     netlink.TUNTAP_NO_PI | netlink.TUNTAP_VNET_HDR,
			Queues:    1,
		}
		if err := netlink.LinkAdd(tap); err != nil {
			return fmt.Errorf("create Kata tap %q: %w", name, err)
		}
		for _, fd := range tap.Fds {
			defer fd.Close()
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetHardwareAddr(link, gatewayHWAddr); err != nil {
			return err
		}
		if err := netlink.AddrReplace(link, actornet.HostVethAddr); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		return nil
	})
}

func cleanupKataNetwork(ctx context.Context, session *actornet.SandboxSession, sandboxID string) error {
	var errs []error
	if err := katashim.RemoveDANConfig(katashim.DefaultDANConfigDir, sandboxID); err != nil {
		errs = append(errs, err)
	}
	if session != nil && session.Network != nil {
		if err := removeKataTap(ctx, session.Network.RuntimeNetNS, kataTapName); err != nil {
			errs = append(errs, err)
		}
	}
	if session != nil {
		if err := session.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeKataTap(ctx context.Context, ns netns.Handle, name string) error {
	return netns.Do(ctx, ns, func(context.Context) error {
		link, err := netlink.LinkByName(name)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				return nil
			}
			return err
		}
		return netlink.LinkDel(link)
	})
}
