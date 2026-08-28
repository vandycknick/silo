package main

import (
	"log"

	"github.com/vandycknick/silo/sdk/go"
)

func main() {
	endpoint := "openai"
	policy, err := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{DefaultAction: silo.NetworkDeny, Endpoints: []silo.NetworkEndpoint{{Name: endpoint, Kind: silo.NetworkEndpointHTTPS, Hosts: []string{"api.openai.com"}}}, Rules: []silo.NetworkRule{{Endpoints: []string{endpoint}, Verdict: silo.NetworkVerdictAllow}}})
	if err != nil {
		log.Fatal(err)
	}
	log.Print(policy.JSON())
}
