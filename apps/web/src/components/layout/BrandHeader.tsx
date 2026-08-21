import { sanitizeImageSrc } from '../../lib/safeImageSrc';
import { useTranslation } from 'react-i18next';

interface BrandHeaderProps {
  /** Partner logo. Sanitized before render; falls back to the default logo when null/unsafe. */
  logoUrl: string | null;
  /** Partner name. Rendered as the text label; the stock product has no wordmark. */
  name: string | null;
  /** Whether to render the text label (hidden in collapsed sidebar mode). */
  showLabel: boolean;
}

const DEFAULT_LOGO = <img src="/branding.png" alt="" className="h-full w-full object-contain" />;

export default function BrandHeader({ logoUrl, name, showLabel }: BrandHeaderProps) {
  const { t } = useTranslation('common');
  const safeLogoUrl = sanitizeImageSrc(logoUrl);
  const partnerName = name?.trim() ?? '';
  // Alt text still needs a brand word even when no wordmark is rendered.
  const altBrand = partnerName || 'Breeze';

  return (
    <div className="flex items-center gap-2">
      {/* Capped at 48px: the sidebar header is h-16 and the collapsed rail is
          w-16, so a larger mark overflows both. */}
      <div className="flex h-12 w-12 shrink-0 items-center justify-center overflow-hidden">
        {safeLogoUrl ? (
          <img src={safeLogoUrl} alt={t('layout.logoAlt', { brand: altBrand })} className="h-full w-full object-contain" />
        ) : (
          DEFAULT_LOGO
        )}
      </div>
      {showLabel && partnerName && (
        <span className="text-lg font-bold tracking-tight text-foreground truncate">{partnerName}</span>
      )}
    </div>
  );
}
