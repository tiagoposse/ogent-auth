package authorization

import (
	"fmt"

	"entgo.io/contrib/entoas"
	"entgo.io/ent/entc/gen"
	authz "github.com/tiagoposse/go-auth/authorization"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type ScopeMutator func(scopes map[string]authz.Scopes)

func ExtractGraphScopes(graph *gen.Graph) map[string]authz.Scopes {
	var graphAnn AuthorizationAnnotation
	if err := graphAnn.Decode(graph.Annotations[graphAnn.Name()]); err != nil {
		return nil
	}

	scopes := make(map[string]authz.Scopes)

	for _, node := range graph.Nodes {
		nodeAnn := AuthorizationAnnotation{}
		nodeAnn = nodeAnn.Merge(graphAnn)

		extractNodeAnn := node.Annotations[nodeAnn.Name()]
		if extractNodeAnn != nil {
			var tempAnn AuthorizationAnnotation
			if err := tempAnn.Decode(extractNodeAnn); err != nil {
				return nil
			}
			nodeAnn = nodeAnn.Merge(tempAnn)
		}

		opScopes(node.Name, nodeAnn, scopes)
		for _, edge := range node.Edges {
			edgeAnn := AuthorizationAnnotation{}
			edgeAnn = nodeAnn.Merge(graphAnn)

			extractEdgeAnn := edge.Annotations[edgeAnn.Name()]
			if extractEdgeAnn == nil {
				var tempAnn AuthorizationAnnotation
				if err := tempAnn.Decode(extractEdgeAnn); err != nil {
					return nil
				}
				edgeAnn = edgeAnn.Merge(tempAnn)
			}

			opScopes(fmt.Sprintf("%s%s", node.Name, cases.Title(language.Und).String(edge.Name)), edgeAnn, scopes)
		}
	}

	return scopes
}

func opScopes(opSuffix string, ann AuthorizationAnnotation, scopes map[string]authz.Scopes) {
	if ann.CreateScopes != nil {
		scopes[fmt.Sprintf("%s%s", entoas.OpCreate, opSuffix)] = ann.CreateScopes
	}
	if ann.DeleteScopes != nil {
		scopes[fmt.Sprintf("%s%s", entoas.OpDelete, opSuffix)] = ann.DeleteScopes
	}
	if ann.ListScopes != nil {
		scopes[fmt.Sprintf("%s%s", entoas.OpList, opSuffix)] = ann.ListScopes
	}
	if ann.ReadScopes != nil {
		scopes[fmt.Sprintf("%s%s", entoas.OpRead, opSuffix)] = ann.ReadScopes
	}
	if ann.UpdateScopes != nil {
		scopes[fmt.Sprintf("%s%s", entoas.OpUpdate, opSuffix)] = ann.UpdateScopes
	}
}
