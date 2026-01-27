package folkloreUC

import "DaraTilBackendV2/internal/domain/interfaces"

type CreateFolkloreUC struct {
	Repo interfaces.FolkloreRepo
}

func NewCreateFolkloreUC(repo interfaces.FolkloreRepo) *CreateFolkloreUC {
	return &CreateFolkloreUC{
		Repo: repo,
	}
}

func (uc CreateFolkloreUC) Execute
