import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { isJwtExpirado } from '../utils/jwt.utils';

export const authGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const tokenAtual = auth.token();

  if (!tokenAtual || isJwtExpirado(tokenAtual)) {
    auth.logout();
    return router.createUrlTree(['/login']);
  }

  return true;
};