package ida

import "context"

// InspectionQueryBackend exposes only the fixed, bounded inspection RPCs.
type InspectionQueryBackend interface {
	SourceFiles(context.Context, string, IndexListParams) (SourceFilesResult, error)
	SourceLines(context.Context, string, SourceLinesParams) (SourceLinesResult, error)
	NameDemangle(context.Context, string, NameDemangleParams) (NameDemangleResult, error)
	CommentGet(context.Context, string, CommentGetParams) (CommentResult, error)
	BookmarkList(context.Context, string, IndexListParams) (BookmarksResult, error)
	TypeXrefs(context.Context, string, TypeXrefsParams) (TypeXrefsResult, error)
	DecompilerLocals(context.Context, string, DecompilerLocalsParams) (DecompilerLocalsResult, error)
	DecompilerCtree(context.Context, string, DecompilerCtreeParams) (DecompilerCtreeResult, error)
	DecompilerLocalXrefs(context.Context, string, DecompilerLocalXrefsParams) (DecompilerLocalXrefsResult, error)
	DebuggerThreads(context.Context, string, IndexListParams) (DebuggerThreadsResult, error)
	DebuggerModules(context.Context, string, IndexListParams) (DebuggerModulesResult, error)
}
