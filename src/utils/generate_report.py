import matplotlib.pyplot as plt
def generate_report(self):
        total = self.stats["success"] + self.stats["failed"]
        if total == 0:
            return
            
        print(f"\n{'='*50}\n[*] COMPILATION RUN COMPLETE\n{'='*50}")
        print(f"Total Processed: {total}")
        print(f"Successful:      {self.stats['success']} ({(self.stats['success']/total)*100:.1f}%)")
        print(f"Failed:          {self.stats['failed']} ({(self.stats['failed']/total)*100:.1f}%)")
        
        labels = ['Successful', 'Failed']
        sizes = [self.stats['success'], self.stats['failed']]
        colors = ['#4CAF50', '#F44336']
        explode = (0.1, 0) if self.stats['success'] > 0 else (0, 0)
        
        plt.figure(figsize=(6, 6))
        plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=140)
        plt.title('Agentic Compiler Rebuild Statistics')
        
        chart_path = "compilation_report.png"
        plt.savefig(chart_path)
        print(f"[+] Saved visual report to: {chart_path}")