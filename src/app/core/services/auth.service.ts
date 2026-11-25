import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { tap } from 'rxjs';
import { environment } from '../../../environments/environment';
import { LoginRequest, LoginResponse } from '../../models/auth.model';
import { decodificarJwtPayload, isJwtExpirado } from '../utils/jwt.utils';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private chave = 'financeiro.sessao';
  private sessao = signal<LoginResponse | null>(this.restaurar());

  // Feedback específico para 403 sem encerrar a sessão
  readonly avisoAcessoNegado = signal<string | null>(null);

  readonly token = computed(() => {
    const atual = this.sessao()?.token ?? null;
    if (!atual) return null;
    if (isJwtExpirado(atual)) {
      return null;
    }
    return atual;
  });

  readonly autenticado = computed(() => !!this.token());

  private readonly claims = computed(() => {
    const t = this.token();
    return t ? decodificarJwtPayload(t) : null;
  });

  // Se houver claim "nome", exibe; caso contrário, "Usuário autenticado"
  readonly nomeUsuario = computed(() => {
    const nome = this.claims()?.nome;
    return typeof nome === 'string' && nome.trim().length > 0
      ? nome.trim()
      : 'Usuário autenticado';
  });

  // Se houver claim "perfil", expõe; se não houver, fica null (condicionado ao backend)
  readonly perfilUsuario = computed(() => {
    const perfil = this.claims()?.perfil;
    return typeof perfil === 'string' && perfil.trim().length > 0
      ? perfil.trim().toUpperCase()
      : null;
  });

  // Oculta menu Usuários apenas quando o backend enviar explicitamente OPERADOR
  readonly podeVerUsuarios = computed(() => this.perfilUsuario() !== 'OPERADOR');

  login(dados: LoginRequest) {
    this.limparAvisoAcessoNegado();
    return this.http.post<LoginResponse>(
      `${environment.apiUrl}/auth/login`, dados
    ).pipe(tap(res => {
      sessionStorage.setItem(this.chave, JSON.stringify(res));
      this.sessao.set(res);
    }));
  }

  logout() {
    sessionStorage.removeItem(this.chave);
    this.sessao.set(null);
    this.limparAvisoAcessoNegado();
  }

  registrarAcessoNegado(mensagem = 'Acesso negado (403): você não tem permissão para realizar esta ação.') {
    this.avisoAcessoNegado.set(mensagem);
  }

  limparAvisoAcessoNegado() {
    this.avisoAcessoNegado.set(null);
  }

  private restaurar(): LoginResponse | null {
    try {
      const raw = sessionStorage.getItem(this.chave);
      if (!raw) return null;
      const parsed = JSON.parse(raw) as LoginResponse | null;
      if (!parsed?.token || isJwtExpirado(parsed.token)) {
        sessionStorage.removeItem(this.chave);
        return null;
      }
      return parsed;
    } catch {
      sessionStorage.removeItem(this.chave);
      return null;
    }
  }
}