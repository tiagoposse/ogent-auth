package authentication

import (
	"fmt"

	"entgo.io/contrib/entoas"
	"entgo.io/ent/entc/gen"
	"github.com/ogen-go/ogen"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func createReqs(schemes map[string]ogen.SecurityRequirement, filter []SecuritySchemeType) ogen.SecurityRequirements {
	filtered := make(ogen.SecurityRequirements, 0)
	for _, f := range filter {
		filtered = append(filtered, schemes[string(f)])
	}
	return filtered
}

// SecurityMutation provides an EntOAS mutation that adds the security schemes as components of the API and as security for paths
func SecurityMutation(opts ...MutatorSchemeOpt) func(graph *gen.Graph, spec *ogen.Spec) error {
	return func(graph *gen.Graph, spec *ogen.Spec) error {
		securityMapping := make(map[string][]SecuritySchemeType)
	
		if spec.Components == nil {
			spec.Components = &ogen.Components{}
		}
		
		if spec.Components.SecuritySchemes == nil {
			spec.Components.SecuritySchemes = make(map[string]*ogen.SecurityScheme)
		}

		for _, opt := range opts {
			opt(spec, securityMapping)
		}

		defaultSchemes := make(map[string]ogen.SecurityRequirement)
		for k := range spec.Components.SecuritySchemes {
			defaultSchemes[k] = map[string][]string{k: {}}
		}
	
		var graphAnn AuthenticationAnnotation
		if err := graphAnn.Decode(graph.Annotations[graphAnn.Name()]); err != nil {
			return err
		}

		if err := extractGraphSecurity(securityMapping, graphAnn, graph); err != nil {
			return err
		}
	
		for _, pathItem := range spec.Paths {
			pathItem := pathItem
			if pathItem.Get != nil {
				if filter, ok := securityMapping[pathItem.Get.OperationID]; ok {
					pathItem.Get.Security = createReqs(defaultSchemes, filter)
				}
			}

			if pathItem.Post != nil {
				if filter, ok := securityMapping[pathItem.Post.OperationID]; ok {
					pathItem.Post.Security = createReqs(defaultSchemes, filter)
				}
			}

			if pathItem.Delete != nil {
				if filter, ok := securityMapping[pathItem.Delete.OperationID]; ok {
					pathItem.Delete.Security = createReqs(defaultSchemes, filter)
				}
			}

			if pathItem.Put != nil {
				if filter, ok := securityMapping[pathItem.Put.OperationID]; ok {
					pathItem.Put.Security = createReqs(defaultSchemes, filter)
				}
			}
		}

		return nil
	}
}

func extractGraphSecurity(securityMapping map[string][]SecuritySchemeType, graphAnn AuthenticationAnnotation, graph *gen.Graph) error {	
	for _, node := range graph.Nodes {
		nodeAnn := AuthenticationAnnotation{}
		nodeAnn = nodeAnn.Merge(graphAnn)

		extractNodeAnn := node.Annotations[nodeAnn.Name()]
		if extractNodeAnn != nil {
			var tempAnn AuthenticationAnnotation
			if err := tempAnn.Decode(extractNodeAnn); err != nil {
				return err
			}
			nodeAnn = nodeAnn.Merge(tempAnn)
		}

		opSecurity(node.Name, nodeAnn, securityMapping)
		for _, edge := range node.Edges {
			edgeAnn := AuthenticationAnnotation{}
			edgeAnn = nodeAnn.Merge(graphAnn)

			extractEdgeAnn := edge.Annotations[edgeAnn.Name()]
			if extractEdgeAnn == nil {
				var tempAnn AuthenticationAnnotation
				if err := tempAnn.Decode(extractEdgeAnn); err != nil {
					return err
				}
				edgeAnn = edgeAnn.Merge(tempAnn)
			}

			opSecurity(fmt.Sprintf("%s%s", node.Name, cases.Title(language.Und).String(edge.Name)), edgeAnn, securityMapping)
		}
	}

	return nil
}

func opSecurity(opSuffix string, ann AuthenticationAnnotation, secMethods map[string][]SecuritySchemeType) {
	if ann.CreateSecurityMethods != nil {
		secMethods[fmt.Sprintf("%s%s", entoas.OpCreate, opSuffix)] = ann.CreateSecurityMethods
	}

	if ann.DeleteSecurityMethods != nil {
		secMethods[fmt.Sprintf("%s%s", entoas.OpDelete, opSuffix)] = ann.DeleteSecurityMethods
	}

	if ann.ListSecurityMethods != nil {
		secMethods[fmt.Sprintf("%s%s", entoas.OpList, opSuffix)] = ann.ListSecurityMethods
	}

	if ann.ReadSecurityMethods != nil {
		secMethods[fmt.Sprintf("%s%s", entoas.OpRead, opSuffix)] = ann.ReadSecurityMethods
	}
	if ann.UpdateSecurityMethods != nil {
		secMethods[fmt.Sprintf("%s%s", entoas.OpUpdate, opSuffix)] = ann.UpdateSecurityMethods
	}
}
