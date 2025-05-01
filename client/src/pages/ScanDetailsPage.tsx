import { useParams } from 'react-router';
import Layout from '../components/common/Layout';
import ScanDetails from '../components/dashboard/ScanDetails';

const ScanDetailsPage = () => {
  const { scanId } = useParams<{ scanId: string }>();
  return (
    <Layout>
      {scanId && <ScanDetails scanId={scanId} />}
    </Layout>
  );
};

export default ScanDetailsPage;