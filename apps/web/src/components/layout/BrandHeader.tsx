import { sanitizeImageSrc } from '../../lib/safeImageSrc';
import { useTranslation } from 'react-i18next';

interface BrandHeaderProps {
  /** Partner logo. Sanitized before render; falls back to the Breeze SVG when null/unsafe. */
  logoUrl: string | null;
  /** Partner name. Falls back to "Breeze" when null/empty. */
  name: string | null;
  /** Whether to render the text label (hidden in collapsed sidebar mode). */
  showLabel: boolean;
}

const BREEZE_SVG = <img src="/branding.png" alt="" className="h-full w-full object-contain" />;

export default function BrandHeader({ logoUrl, name, showLabel }: BrandHeaderProps) {
  const { t } = useTranslation('common');
  const safeLogoUrl = sanitizeImageSrc(logoUrl);
  const label = name?.trim() || 'Breeze';

  return (
    <div className="flex items-center gap-2">
      <div className="flex h-[42px] w-[42px] shrink-0 items-center justify-center overflow-hidden rounded-[6px] bg-primary/15">
        {safeLogoUrl ? (
          <img src={safeLogoUrl} alt={t('layout.logoAlt', { brand: label })} className="h-full w-full object-contain" />
        ) : (
          BREEZE_SVG
        )}
      </div>
      {showLabel && (
        <span className="text-lg font-bold tracking-tight text-foreground truncate">{label}</span>
      )}
    </div>
  );
}
