package cert

import (
	"fmt"
	"time"

	"github.com/schollz/progressbar/v3"
)

// ProgressTracker handles progress reporting during certificate generation
type ProgressTracker struct {
	bar     *progressbar.ProgressBar
	current int
	total   int
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(description string) *ProgressTracker {
	total := 100
	bar := progressbar.NewOptions(total,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(40),
		progressbar.OptionSetDescription(fmt.Sprintf("[cyan]%-30s[reset]", description)),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowCount(),
	)
	return &ProgressTracker{
		bar:     bar,
		current: 0,
		total:   total,
	}
}

// Step advances the progress bar by the specified percentage
func (p *ProgressTracker) Step(percent int) {
	p.current += percent
	if p.current > p.total {
		p.current = p.total
	}
	p.bar.Set(p.current)
}

// Complete marks the progress as complete
func (p *ProgressTracker) Complete() {
	p.bar.Finish()
	fmt.Println() // Add newline after progress bar
}

// GenerationProgress tracks the progress of certificate generation
type GenerationProgress struct {
	KeyGenBar    *ProgressTracker
	TemplateBar  *ProgressTracker
	SigningBar   *ProgressTracker
	SaveBar      *ProgressTracker
	InstallBar   *ProgressTracker
	startTime    time.Time
	description  string
	showProgress bool
}

// NewGenerationProgress creates a new generation progress tracker
func NewGenerationProgress(description string, showProgress bool) *GenerationProgress {
	if !showProgress {
		return &GenerationProgress{
			description:  description,
			showProgress: false,
		}
	}

	fmt.Printf("\n[bold]%s[reset]\n\n", description)

	return &GenerationProgress{
		KeyGenBar:    NewProgressTracker("Generating Key"),
		TemplateBar:  NewProgressTracker("Creating Template"),
		SigningBar:   NewProgressTracker("Signing Certificate"),
		SaveBar:      NewProgressTracker("Saving Files"),
		InstallBar:   NewProgressTracker("Installing Certificate"),
		startTime:    time.Now(),
		description:  description,
		showProgress: true,
	}
}

// StartProgress starts a generic progress operation
func (g *GenerationProgress) StartProgress(description string) {
	if !g.showProgress {
		return
	}
	g.InstallBar = NewProgressTracker(description)
	g.InstallBar.Step(50)
}

// CompleteProgress completes a generic progress operation
func (g *GenerationProgress) CompleteProgress() {
	if !g.showProgress {
		return
	}
	g.InstallBar.Step(50)
	g.InstallBar.Complete()
}

// StartKeyGen starts the key generation progress
func (g *GenerationProgress) StartKeyGen() {
	if !g.showProgress {
		return
	}
	g.startTime = time.Now()
}

// CompleteKeyGen completes the key generation progress
func (g *GenerationProgress) CompleteKeyGen() {
	if !g.showProgress {
		return
	}
	g.KeyGenBar.Step(100)
	g.KeyGenBar.Complete()
}

// StartTemplate starts the template creation progress
func (g *GenerationProgress) StartTemplate() {
	if !g.showProgress {
		return
	}
	g.TemplateBar.Step(50)
}

// CompleteTemplate completes the template creation progress
func (g *GenerationProgress) CompleteTemplate() {
	if !g.showProgress {
		return
	}
	g.TemplateBar.Step(50)
	g.TemplateBar.Complete()
}

// StartSigning starts the certificate signing progress
func (g *GenerationProgress) StartSigning() {
	if !g.showProgress {
		return
	}
	g.SigningBar.Step(50)
}

// CompleteSigning completes the certificate signing progress
func (g *GenerationProgress) CompleteSigning() {
	if !g.showProgress {
		return
	}
	g.SigningBar.Step(50)
	g.SigningBar.Complete()
}

// StartSaving starts the file saving progress
func (g *GenerationProgress) StartSaving() {
	if !g.showProgress {
		return
	}
	g.SaveBar.Step(50)
}

// CompleteSaving completes the file saving progress
func (g *GenerationProgress) CompleteSaving() {
	if !g.showProgress {
		return
	}
	g.SaveBar.Step(50)
	g.SaveBar.Complete()
}

// Complete completes all progress bars and shows completion message
func (g *GenerationProgress) Complete() {
	if !g.showProgress {
		return
	}
	duration := time.Since(g.startTime).Round(time.Millisecond)
	fmt.Printf("\n✨ %s completed in %v\n\n", g.description, duration)
}
