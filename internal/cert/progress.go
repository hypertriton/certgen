package cert

import (
	"fmt"
	"sync"
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
	operation string
	enabled   bool
	startTime time.Time
	mu        sync.Mutex
}

// NewGenerationProgress creates a new progress tracker
func NewGenerationProgress(operation string, enabled bool) *GenerationProgress {
	return &GenerationProgress{
		operation: operation,
		enabled:   enabled,
		startTime: time.Now(),
	}
}

// StartKeyGen indicates the start of key generation
func (p *GenerationProgress) StartKeyGen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("Generating private key for %s...\n", p.operation)
	}
}

// CompleteKeyGen indicates the completion of key generation
func (p *GenerationProgress) CompleteKeyGen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("✓ Private key generated\n")
	}
}

// StartTemplate indicates the start of template creation
func (p *GenerationProgress) StartTemplate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("Creating certificate template for %s...\n", p.operation)
	}
}

// CompleteTemplate indicates the completion of template creation
func (p *GenerationProgress) CompleteTemplate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("✓ Certificate template created\n")
	}
}

// StartSigning indicates the start of certificate signing
func (p *GenerationProgress) StartSigning() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("Signing certificate for %s...\n", p.operation)
	}
}

// CompleteSigning indicates the completion of certificate signing
func (p *GenerationProgress) CompleteSigning() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("✓ Certificate signed\n")
	}
}

// StartSaving indicates the start of file saving
func (p *GenerationProgress) StartSaving() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("Saving certificate and key for %s...\n", p.operation)
	}
}

// CompleteSaving indicates the completion of file saving
func (p *GenerationProgress) CompleteSaving() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("✓ Certificate and key saved\n")
	}
}

// StartLoading indicates the start of certificate loading
func (p *GenerationProgress) StartLoading() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("Loading certificate for %s...\n", p.operation)
	}
}

// CompleteLoading indicates the completion of certificate loading
func (p *GenerationProgress) CompleteLoading() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("✓ Certificate loaded\n")
	}
}

// StartKeyLoading indicates the start of private key loading
func (p *GenerationProgress) StartKeyLoading() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("Loading private key for %s...\n", p.operation)
	}
}

// CompleteKeyLoading indicates the completion of private key loading
func (p *GenerationProgress) CompleteKeyLoading() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("✓ Private key loaded\n")
	}
}

// StartCALoading indicates the start of CA loading
func (p *GenerationProgress) StartCALoading() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("Loading CA certificate and key for %s...\n", p.operation)
	}
}

// CompleteCALoading indicates the completion of CA loading
func (p *GenerationProgress) CompleteCALoading() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("✓ CA certificate and key loaded\n")
	}
}

// Complete indicates the completion of the entire operation
func (p *GenerationProgress) Complete() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		duration := time.Since(p.startTime)
		fmt.Printf("\n%s completed in %s\n", p.operation, duration.Round(time.Millisecond))
	}
}

// CompleteProgress implements the ProgressReporter interface
func (p *GenerationProgress) CompleteProgress() {
	p.Complete()
}

// StartProgress implements the ProgressReporter interface
func (p *GenerationProgress) StartProgress(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enabled {
		fmt.Printf("%s...\n", message)
	}
}
