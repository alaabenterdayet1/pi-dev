import { Component, ChangeDetectionStrategy, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ChatAssistantService } from '../../../core/services/chat-assistant.service';

interface ChatMessage {
  role: 'user' | 'assistant';
  text: string;
}

@Component({
  selector: 'app-security-chatbot',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './security-chatbot.html',
  styleUrl: './security-chatbot.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SecurityChatbotComponent {
  private chatService = inject(ChatAssistantService);

  isOpen = signal(false);
  isLoading = signal(false);
  draft = signal('');
  messages = signal<ChatMessage[]>([
    {
      role: 'assistant',
      text: 'Bonjour. Pose ta question sur le sujet de ton choix. Je peux repondre en mode court ou detaille selon ta demande.',
    },
  ]);

  toggleOpen(): void {
    this.isOpen.set(!this.isOpen());
  }

  send(): void {
    const text = this.draft().trim();
    if (!text || this.isLoading()) return;

    this.messages.update((list) => [...list, { role: 'user', text }]);
    this.draft.set('');
    this.isLoading.set(true);

    this.chatService.ask(text).subscribe((res) => {
      const reply = (res.reply || res.message || 'Reponse indisponible.').trim();
      this.messages.update((list) => [...list, { role: 'assistant', text: reply }]);
      this.isLoading.set(false);
    });
  }
}
